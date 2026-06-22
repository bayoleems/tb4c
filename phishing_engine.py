from __future__ import annotations
import datetime as dt
import ipaddress
import re
from dataclasses import dataclass, field, asdict
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
import tldextract
import whois
from bs4 import BeautifulSoup
from confusable_homoglyphs import confusables
from rapidfuzz.distance import Levenshtein

_TLD = tldextract.TLDExtract()

BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "office365": "office.com",
    "outlook": "outlook.com", "google": "google.com", "gmail": "gmail.com",
    "apple": "apple.com", "icloud": "icloud.com", "amazon": "amazon.com",
    "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com",
    "linkedin": "linkedin.com", "dhl": "dhl.com", "fedex": "fedex.com", "ups": "ups.com",
    "dropbox": "dropbox.com", "docusign": "docusign.com", "hmrc": "gov.uk",
    "dpd": "dpd.co.uk", "santander": "santander.co.uk", "barclays": "barclays.co.uk",
    "hsbc": "hsbc.com", "natwest": "natwest.com", "lloyds": "lloydsbank.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com",
    "coinbase": "coinbase.com", "binance": "binance.com", "whatsapp": "whatsapp.com"
    }
FREEMAIL = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
    "icloud.com", "mail.ru", "proton.me", "protonmail.com", "gmx.com", "yandex.com"
    }
URGENCY_TERMS = [
    "urgent", "immediately", "within 24 hours", "within 48 hours", "act now",
    "as soon as possible", "final notice", "last warning", "account suspended", "available at no cost",
    "suspended", "will expire", "expires", "deactivat", "limited time", "generously",
    "verify now", "action required", "failure to", "avoid suspension", "Don't miss this chance",

    "verification required", "unusual signin", "unusual sign-in", "security alert",
    "account locked", "unauthorized", "confirm your email", "wallet update"
    ]
CRED_TERMS = [
    "verify your account", "confirm your password", "update your password",
    "login to confirm", "verify your identity", "confirm your identity",
    "re-enter your", "validate your account", "unlock your account",
    "confirm your details", "enter your password", "sign in to verify",
    "reset your password", "update your payment", "confirm your billing", "take advantage",
    "seed phrase", "recovery phrase", "private key", "connect your wallet",
    "sync your wallet", "validate your wallet"
    ]
BEC_TERMS = [
    "wire transfer", "gift card", "urgent payment", "change bank", "bank details",
    "are you available", "quick task", "confidential", "invoice attached",
    "update payment", "process payment", "purchase order", "reimbursement",
    "change my direct deposit", "outstanding invoice"
    ]
DANGEROUS_EXTS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".hta", ".jar", ".ps1", ".msi", ".lnk", ".iso",
    ".img", ".reg", ".cpl", ".gadget", ".inf"
    }
MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xltm"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".cab", ".ace", ".tar"}
DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv|html?)\.(exe|scr|js|vbs|"
    r"bat|cmd|com|jar|hta|msi|lnk|iso|ps1)$",
    re.I
    )
GREETING = re.compile(
    r"\b(dear\s+(valued\s+)?(customer|client|user|member|student|account\s*holder|"
    r"sir(\s+or\s+madam)?|madam)|to\s+whom\s+it\s+may\s+concern|"
    r"dear\s+(account|email)\s*(holder|owner)?|hello\s+(dear\s+)?(customer|user|member))\b",
    re.I
    )
# Each value is the check's share out of 10 (e.g. 15 → 1.5/10). Sum = 100.
WEIGHTS = {
    "domain_age": 7,
    "typosquatting": 13,
    "urgency_cred": 13,
    "url_ip": 7,
    "bec": 11,
    "reply_mismatch": 15,
    "attachments": 6,
    "display_spoof": 12,
    "generic_greeting": 6,
    "link_mismatch": 10
    }
WEIGHT_TOTAL = sum(WEIGHTS.values()) 
DEFAULT_THRESHOLDS = {
    "suspicious": 10, 
    "high": 25, 
    "critical": 50
    }

def domain_of(addr: str) -> str:
    return addr.split("@")[-1].lower().strip() if addr and "@" in addr else ""


def registered_domain(host: str) -> str:
    host = (host or "").lower().strip().rstrip(".")
    return _TLD(host).registered_domain or host


def _host_of(href: str) -> str:
    if not href:
        return ""
    if "://" not in href:
        href = "http://" + href
    try:
        return (urlparse(href).hostname or "").lower()
    except Exception:
        return ""


def _strip_html(html: str) -> str:
    if not html:
        return ""
    return BeautifulSoup(html, "html.parser").get_text(" ", strip=True)


def _links_from_html(html: str) -> list[tuple[str, str]]:
    if not html:
        return []
    out = []
    for a in BeautifulSoup(html, "html.parser").find_all("a"):
        href = a.get("href") or ""
        if href:
            out.append((a.get_text(" ", strip=True), href))
    return out


def _urls_from_text(text: str) -> list[tuple[str, str]]:
    if not text:
        return []
    return [(u, u) for u in re.findall(r'https?://[^\s<>"\')\]]+', text) if u]


@dataclass
class NormalizedEmail:
    display: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    text: str = ""
    html: str = ""
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)

    @property
    def sender_domain(self) -> str:
        return domain_of(self.sender)

    @property
    def body(self) -> str:
        return (self.text or "") + ("\n" + _strip_html(self.html) if self.html else "")


def parse_eml_bytes(data: bytes) -> NormalizedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    email = NormalizedEmail()
    email.display, email.sender = parseaddr(msg.get("From", ""))
    email.reply_to = parseaddr(msg.get("Reply-To", ""))[1]
    email.return_path = parseaddr(msg.get("Return-Path", ""))[1]
    email.subject = msg.get("Subject", "")
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fn = part.get_filename()
        if part.get_content_disposition() == "attachment" or fn:
            email.attachments.append(fn or "(unnamed)")
            continue
        try:
            content = part.get_content()
        except Exception:
            content = ""
        if ctype == "text/plain":
            email.text += content
        elif ctype == "text/html":
            email.html += content
    email.links = _links_from_html(email.html) + _urls_from_text(email.text)
    return email


def load_email_from_bytes(data: bytes, filename: str = "") -> NormalizedEmail:
    if filename and "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()
    else:
        ext = ".eml"
    if ext not in (".eml", ".txt"):
        raise ValueError(f"Unsupported format: {ext!r} (expected .eml)")
    return parse_eml_bytes(data)


def load_email(path: str) -> NormalizedEmail:
    with open(path, "rb") as fh:
        return load_email_from_bytes(fh.read(), path)


@dataclass
class CheckResult:
    id: str
    name: str
    risk: int = 0
    weight: float = 0.0
    evidence: list = field(default_factory=list)
    recommendation: str = ""

    @property
    def severity(self) -> str:
        if self.risk < 10:
            return "none"
        if self.risk < 35:
            return "low"
        if self.risk < 65:
            return "medium"
        return "high"

    @property
    def weighted(self) -> float:
        # weight is share-out-of-10 (×10); divide by 100 to scale risk to /100.
        return round(self.risk * self.weight / WEIGHT_TOTAL, 2)


def _as_utc(d: dt.datetime) -> dt.datetime:
    if d.tzinfo is None:
        return d.replace(tzinfo=dt.timezone.utc)
    return d


def check_domain_age(email: NormalizedEmail, *, enable_whois: bool = False) -> CheckResult:
    c = CheckResult("domain_age", "1. Domain age", weight=WEIGHTS["domain_age"])
    dom = registered_domain(email.sender_domain)
    if not dom:
        c.evidence.append("No sender domain available.")
        c.recommendation = "Verify sender out-of-band."
        return c
    if not enable_whois:
        c.evidence.append("Domain-age check skipped (WHOIS disabled).")
        return c
    try:
        creation = whois.whois(dom).creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if not creation:
            c.evidence.append(f"No creation date found for {dom}.")
            return c
        created = _as_utc(creation)
        age = (dt.datetime.now(dt.timezone.utc) - created).days
        c.evidence.append(f"{dom} registered {age} days ago ({created.date()}).")
        if age < 30:
            c.risk, c.recommendation = 90, "Very new domain — strong phishing indicator."
        elif age < 90:
            c.risk, c.recommendation = 65, "Recently registered — treat with caution."
        elif age < 365:
            c.risk = 30
        else:
            c.risk = 10
    except Exception as ex:
        c.evidence.append(f"WHOIS lookup failed: {ex}")
    return c


def check_typosquatting(email: NormalizedEmail, org_domains: set[str]) -> CheckResult:
    c = CheckResult("typosquatting", "2. Typosquatting", weight=WEIGHTS["typosquatting"])
    official = set(BRANDS.values()) | org_domains
    domains = set()
    if email.sender_domain:
        domains.add(email.sender_domain)
    for _, href in email.links:
        if h := _host_of(href):
            domains.add(h)
    for d in domains:
        rd = registered_domain(d)
        label = rd.split(".")[0] if rd else d
        if "xn--" in d:
            c.risk = max(c.risk, 80)
            c.evidence.append(f"IDN/punycode domain (possible homograph attack): {d}")
        if confusables.is_dangerous(d):
            c.risk = max(c.risk, 82)
            c.evidence.append(f"Mixed-script confusable characters in: {d}")
        if rd in official:
            continue
        labels = set(re.split(r"[.\-_]", d))
        for brand, official_domain in BRANDS.items():
            if rd == official_domain:
                continue
            if brand in labels and len(brand) >= 4:
                c.risk = max(c.risk, 72)
                c.evidence.append(f'Brand "{brand}" used inside non-official domain: {d}')
            elif (
                (dist := Levenshtein.distance(label, brand))
                and 0 < dist <= 2
                and len(brand) >= 5
                and abs(len(label) - len(brand)) <= 2
            ):
                c.risk = max(c.risk, 70)
                c.evidence.append(f'"{d}" closely resembles "{brand}" (edit distance {dist}).')
    if c.risk:
        c.recommendation = "Confirm the true domain; do not trust the displayed brand."
    return c


def check_urgency_cred(email: NormalizedEmail) -> CheckResult:
    c = CheckResult("urgency_cred", "3. Urgency and Credential harvesting", weight=WEIGHTS["urgency_cred"])
    blob = (email.subject + " " + email.body).lower()
    urgency = [t for t in URGENCY_TERMS if t in blob]
    cred = [t for t in CRED_TERMS if t in blob]
    c.risk = min(100, len(urgency) * 15 + len(cred) * 30)
    if urgency:
        c.evidence.append("Urgency cues: " + ", ".join(sorted(set(urgency))[:5]))
    if cred:
        c.evidence.append("Credential-harvesting language: " + ", ".join(sorted(set(cred))[:4]))
    if c.risk:
        c.recommendation = "Never enter credentials from email links; navigate to the site directly."
    return c


def check_url_ip(email: NormalizedEmail) -> CheckResult:
    c = CheckResult("url_ip", "4. URL with IP address", weight=WEIGHTS["url_ip"])
    count = 0
    ip_links = []

    for _, href in email.links:
        host = _host_of(href)
        try:
            ipaddress.ip_address(host)
            ip_links.append(href)
        except ValueError:
            pass

    count = len(ip_links)

    if count == 1:
        c.risk = max(c.risk, 85)
        c.evidence.append(f"Link uses a raw IP address: {ip_links[0]}")
    elif count > 1:
        if count > 3:
            c.risk = 100
            # Optionally, show just a sample of IP links (to not spam evidence)
            shown = ", ".join(ip_links[:3])
            more = f" (+{count-3} more)" if count > 3 else ""
            c.evidence.append(f"{count} links use raw IP addresses: {shown}{more}")
        else:
            c.risk = max(c.risk, 95)
            shown = ", ".join(ip_links)
            c.evidence.append(f"{count} links use raw IP addresses: {shown}")

    if c.risk:
        c.recommendation = "Legitimate brands rarely link to raw IPs; block/quarantine."
    return c


def check_bec(email: NormalizedEmail) -> CheckResult:
    c = CheckResult("bec", "5. BEC patterns", weight=WEIGHTS["bec"])
    blob = (email.subject + " " + email.body).lower()
    hits = [t for t in BEC_TERMS if t in blob]
    if hits:
        c.risk += min(60, len(hits) * 20)
        c.evidence.append("BEC language: " + ", ".join(hits[:4]))
    free = email.sender_domain in FREEMAIL
    if (
        free
        and email.display
        and len(email.display.split()) >= 2
        and re.search(r"\b(ceo|cfo|coo|director|president|manager|payroll|finance|hr)\b", blob)
    ):
        c.risk += 20
        c.evidence.append("Role impersonation from a free email address.")
    if email.reply_to and registered_domain(domain_of(email.reply_to)) != registered_domain(email.sender_domain):
        c.risk += 15
        c.evidence.append("Reply-To diverts responses off-domain (common in BEC).")
    if free and any(w in blob for w in ["gift card", "wire", "bank details", "invoice", "payment"]):
        c.risk += 15
    c.risk = min(100, c.risk)
    if c.risk >= 35:
        c.recommendation = "Verify any payment/financial request via a known phone number."
    return c


def check_reply_mismatch(email: NormalizedEmail) -> CheckResult:
    c = CheckResult("reply_mismatch", "6. From and Reply-To domain mismatch", weight=WEIGHTS["reply_mismatch"])
    from_dom = registered_domain(email.sender_domain)
    reply_dom = registered_domain(domain_of(email.reply_to)) if email.reply_to else ""
    return_dom = registered_domain(domain_of(email.return_path)) if email.return_path else ""
    if from_dom and reply_dom and reply_dom != from_dom:
        c.risk = max(c.risk, 65)
        c.evidence.append(f"Reply-To domain ({reply_dom}) differs from From ({from_dom}).")
    if from_dom and return_dom and return_dom != from_dom:
        c.risk = max(c.risk, 25)
        c.evidence.append(f"Return-Path domain ({return_dom}) differs from From ({from_dom}).")
    if c.risk >= 35:
        c.recommendation = "Replies leave the sender's stated domain — treat as suspicious."
    return c


def check_attachments(email: NormalizedEmail) -> CheckResult:
    c = CheckResult("attachments", "7. Dangerous attachments", weight=WEIGHTS["attachments"])
    for name in email.attachments:
        fn = name.lower()
        ext = "." + fn.rsplit(".", 1)[-1] if "." in fn else ""
        if DOUBLE_EXT.search(fn):
            c.risk = max(c.risk, 95)
            c.evidence.append(f"Double-extension (executable in disguise): {name}")
        elif ext in DANGEROUS_EXTS:
            c.risk = max(c.risk, 90)
            c.evidence.append(f"Dangerous executable attachment: {name}")
        elif ext in MACRO_EXTS:
            c.risk = max(c.risk, 70)
            c.evidence.append(f"Macro-enabled document: {name}")
        elif ext in ARCHIVE_EXTS:
            c.risk = max(c.risk, 40)
            c.evidence.append(f"Archive attachment (inspect contents): {name}")
    if c.risk:
        c.recommendation = "Do not open; detonate in a sandbox or delete."
    return c


def check_display_spoof(email: NormalizedEmail, org_domains: set[str]) -> CheckResult:
    c = CheckResult("display_spoof", "8. Display-name spoofing", weight=WEIGHTS["display_spoof"])
    display = email.display or ""
    low = display.lower()
    if (m := re.search(r"[\w.+-]+@[\w.-]+\.\w+", display)) and domain_of(m.group(0)) != email.sender_domain:
        c.risk = max(c.risk, 75)
        c.evidence.append(
            f'Display name embeds a different address ("{display}") vs actual {email.sender}.'
        )
    from_dom = registered_domain(email.sender_domain)
    for brand, official in BRANDS.items():
        if brand in low and from_dom != official and from_dom not in org_domains:
            c.risk = max(c.risk, 68)
            c.evidence.append(
                f'Display name claims "{brand}" but sender domain is {email.sender_domain or "unknown"}.'
            )
            break
    if (
        (m := re.search(r"\b([\w-]+\.(?:com|net|org|io|co|gov|edu)[\w.]*)\b", low))
        and registered_domain(m.group(1)) != from_dom
        and from_dom
    ):
        c.risk = max(c.risk, 55)
        c.evidence.append(f'Display name shows domain "{m.group(1)}" not matching {from_dom}.')
    if c.risk:
        c.recommendation = "Inspect the real address, not the display name."
    return c


def check_generic_greeting(email: NormalizedEmail) -> CheckResult:
    c = CheckResult("generic_greeting", "9. Generic greeting", weight=WEIGHTS["generic_greeting"])
    if GREETING.search(email.body):
        c.risk = 45
        c.evidence.append("Impersonal greeting (e.g. 'Dear Customer / Sir or Madam').")
        c.recommendation = "Legitimate providers usually personalise greetings — minor signal."
    return c


def check_link_mismatch(email: NormalizedEmail, org_domains: set[str]) -> CheckResult:
    c = CheckResult("link_mismatch", "10. Link text vs actual URL", weight=WEIGHTS["link_mismatch"])
    for text, href in email.links:
        if "://" not in (href or ""):
            continue
        href_dom = registered_domain(_host_of(href))
        if not text:
            continue
        m = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", text.lower())
        if m:
            text_dom = registered_domain(m.group(1))
            if text_dom and href_dom and text_dom != href_dom:
                c.risk = max(c.risk, 78)
                c.evidence.append(f'Link text shows "{m.group(1)}" but points to {href_dom}.')
        for brand, official in BRANDS.items():
            if (
                brand in text.lower()
                and href_dom
                and registered_domain(official) != href_dom
                and href_dom not in org_domains
            ):
                c.risk = max(c.risk, 60)
                c.evidence.append(f'Link text mentions "{brand}" but href goes to {href_dom}.')
                break
    if c.risk:
        c.recommendation = "Hover/verify the true destination before clicking."
    return c


def classify(score: float, thresholds: dict | None = None) -> tuple[str, str]:
    t = thresholds or DEFAULT_THRESHOLDS
    if score >= t["critical"]:
        return "malicious", "BLOCK"
    if score >= t["high"]:
        return "phishing", "QUARANTINE"
    if score >= t["suspicious"]:
        return "suspicious", "FLAG"
    return "legitimate", "DELIVER"


@dataclass
class AnalysisResult:
    email: NormalizedEmail
    checks: list
    overall_risk: int
    classification: str
    action: str
    recommendations: list
    thresholds: dict

    def to_dict(self) -> dict:
        return {
            "from": self.email.sender,
            "subject": self.email.subject,
            "overall_risk": self.overall_risk,
            "classification": self.classification,
            "action": self.action,
            "recommendations": self.recommendations,
            "checks": [
                asdict(c) | {"severity": c.severity, "weighted": c.weighted}
                for c in self.checks
            ],
        }
    
    def rows(self) -> list[dict]:
        # Flatten each check into its own row for structured DataFrame use
        rows = []
        for check in self.checks:
            row = {
                "from": self.email.sender,
                "subject": self.email.subject,
                "overall_risk": self.overall_risk,
                "classification": self.classification,
                "action": self.action,
                "recommendations": self.recommendations,
                "check_name": check.name,
                "check_risk": check.risk,
                "check_severity": check.severity,
                "check_weighted": check.weighted,
                "check_evidence": check.evidence,
            }
            rows.append(row)
        return rows
 
    def report(self) -> str:
        risk = int(round(float(self.overall_risk)))
        filled = risk // 4
        bar = "█" * filled + "░" * (25 - filled)
        risk_label = (
            f"{self.overall_risk:.2f}"
            if isinstance(self.overall_risk, float) and self.overall_risk != int(self.overall_risk)
            else str(risk)
        )
        lines = [
            " PHISHING TRIAGE REPORT",
            "=" * 64,
            f" From    : {self.email.display} <{self.email.sender}>",
            f" Subject : {self.email.subject}",
            "=" * 64,
            f" RISK SCORE : {risk_label:>6}/100  [{bar}]",
            f" VERDICT    : {self.classification}",
            f" ACTION     : {self.action}",
            "=" * 64,
            " CHECK BREAKDOWN:",
        ]
        for check in self.checks:
            flag = {"none": " ", "low": "·", "medium": "!", "high": "✗"}[check.severity]
            lines.append(f"  [{flag}] {check.name:<38} risk {check.risk:>3}  (wt {check.weighted:>5})")
            for ev in check.evidence:
                lines.append(f"        - {ev}")
        lines += ["=" * 64, " RECOMMENDATIONS:"]
        lines += [f"  • {r}" for r in self.recommendations] or ["  • None — no strong indicators."]
        lines.append("=" * 64)
        return "\n".join(lines)


def analyze_email(
    email: NormalizedEmail,
    *,
    org_domains: list[str] | None = None,
    enable_whois: bool = False,
    thresholds: dict | None = None
    ) -> AnalysisResult:
    org = {d.lower() for d in (org_domains or [])}
    checks = [
        check_domain_age(email, enable_whois=enable_whois),
        check_typosquatting(email, org),
        check_urgency_cred(email),
        check_url_ip(email),
        check_bec(email),
        check_reply_mismatch(email),
        check_attachments(email),
        check_display_spoof(email, org),
        check_generic_greeting(email),
        check_link_mismatch(email, org),
    ]
    overall = max(0, min(100, round(sum(c.weighted for c in checks), 2)))
    label, action = classify(overall, thresholds)
    recs = []
    for check in sorted(checks, key=lambda c: -c.risk):
        if check.risk >= 35 and check.recommendation and check.recommendation not in recs:
            recs.append(check.recommendation)
    if action in ("BLOCK", "QUARANTINE"):
        recs.insert(0, f"Overall action: {action} this message and report to your SOC.")
    return AnalysisResult(email, checks, overall, label, action, recs, thresholds or DEFAULT_THRESHOLDS)


def analyze_bytes(data: bytes, filename: str = "", **kwargs) -> AnalysisResult:
    return analyze_email(load_email_from_bytes(data, filename), **kwargs)


def analyze_file(path: str, **kwargs) -> AnalysisResult:
    return analyze_email(load_email(path), **kwargs)