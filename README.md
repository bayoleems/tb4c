# TB4C — Phishing Email Triage

A rule-based phishing analysis tool built for the **YSJU London Campus Cyber Defence Hackathon 2026**. Upload a raw `.eml` file and get a risk score, classification, recommended action, and a breakdown of ten phishing indicators.

## Problem / challenge

Security teams and analysts often receive suspicious emails that need fast, explainable triage. Manual review is slow, and black-box tools do not always show *why* a message was flagged. This project addresses that gap by parsing email files and scoring them against transparent, weighted heuristics for common phishing and business-email-compromise (BEC) patterns.

## Tech stack

| Layer | Technologies |
|-------|--------------|
| Core engine | Python 3 (`phishing_engine.py`) |
| Web UI | [Streamlit](https://streamlit.io/) |
| Analysis & exploration | Jupyter (`phishing_basic.ipynb`), [pandas](https://pandas.pydata.org/) |
| Parsing & detection | BeautifulSoup, `tldextract`, RapidFuzz, `confusable-homoglyphs`, `python-whois` |

## Setup and run

### Prerequisites

- Python 3.10+ recommended
- Internet access if WHOIS domain-age lookups are enabled

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the web app

```bash
streamlit run app.py
```

Open the URL shown in the terminal (usually `http://localhost:8501`), upload an `.eml` file, and review the results.

**Sidebar options**

- **Enable WHOIS lookups** — checks sender domain age (slower; requires network).
- **Organization domains** — comma-separated trusted internal domains (e.g. `example.com`) so typosquatting and display-name checks treat them as legitimate.

### 3. Analyze from Python or the notebook

```python
from phishing_engine import analyze_file, load_email, analyze_email

result = analyze_file("sample/sample-21.eml", enable_whois=True)
print(result.report())
```

Or open `phishing_basic.ipynb` for single-email and batch examples against the included `sample/` files.

## How it works

The engine parses `.eml` messages and runs **10 weighted checks**:

1. Domain age (WHOIS)
2. Typosquatting / homoglyph detection
3. Urgency and credential-harvesting language
4. URLs using raw IP addresses
5. BEC patterns
6. From / Reply-To / Return-Path domain mismatch
7. Dangerous attachments
8. Display-name spoofing
9. Generic greetings
10. Link text vs actual URL mismatch

Checks are combined into an overall risk score (0–100) and mapped to a classification and action:

| Risk score | Classification | Action |
|------------|----------------|--------|
| &lt; 10 | legitimate | DELIVER |
| 10–24 | suspicious | FLAG |
| 25–49 | phishing | QUARANTINE |
| ≥ 50 | malicious | BLOCK |

## Team members

<!-- Update with your full team roster -->
- Saleem Adebayo
- Samuel Poopola
- Oluwatomisin Rahman
- Prosper Akarah

## Usage notes, limitations, and next steps

**Notes**

- Sample emails are in `sample/` for testing and demos.
- WHOIS results depend on registrar data and may fail or be rate-limited.
- Set organization domains when analyzing internal mail so trusted senders are not false-flagged.

**Limitations**

- Rule-based scoring is used and not machine learning, therefore highly targeted attacks may be missed.
- English-centered keyword lists are used for urgency, credential, and BEC detection. Other languages might be missed.
- Supports `.eml` formart only
- Does not validate SPF, DKIM, or DMARC authentication headers.

**Possible next steps**

- Add SPF/DKIM/DMARC header checks and sandbox attachment detonation.
- Tune thresholds and weights from labeled training data.
- Deploy behind authentication for production use.

## Built during the hackathon

Everything in this repository was created for the hackathon:

- **`phishing_engine.py`** — email parser, ten phishing/BEC checks, weighted scoring, and text report generation.
- **`app.py`** — Streamlit upload UI with risk summary, breakdown table, and full report.
- **`phishing_basic.ipynb`** — interactive analysis testing on sample emails.