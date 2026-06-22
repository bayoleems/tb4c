import pandas as pd
import streamlit as st
from phishing_engine import analyze_bytes

st.set_page_config(page_title="Phishing Triage", page_icon="🛡️", layout="wide")

CLASSIFICATION_COLORS = {
    "legitimate": "#22c55e",
    "suspicious": "#eab308",
    "phishing": "#f97316",
    "malicious": "#ef4444"
    }


def render_result(result) -> None:
    color = CLASSIFICATION_COLORS.get(result.classification, "#94a3b8")

    st.markdown(
        f"""
        <div style="padding: 1rem 1.25rem; border-radius: 0.5rem; border-left: 4px solid {color};
                    background: rgba(148, 163, 184, 0.08); margin-bottom: 1rem;">
            <div style="font-size: 1.5rem; font-weight: 600; color: {color};">
                {result.classification.upper()} — {result.action}
            </div>
            <div style="color: #64748b; margin-top: 0.25rem;">
                Risk score {result.overall_risk}/100
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk score", f"{result.overall_risk}/100")
    col2.metric("Classification", result.classification)
    col3.metric("Recommended action", result.action)

    st.subheader("Email details")
    st.write(f"**From:** {result.email.display} `<{result.email.sender}>`")
    st.write(f"**Subject:** {result.email.subject}")
    if result.email.reply_to:
        st.write(f"**Reply-To:** {result.email.reply_to}")

    if result.recommendations:
        st.subheader("Recommendations")
        for rec in result.recommendations:
            st.markdown(f"- {rec}")

    st.subheader("Check breakdown")
    checks_df = pd.DataFrame(
        [
            {
                "check": c.name,
                "risk": c.risk,
                "severity": c.severity,
                "weighted": c.weighted,
                "evidence": "; ".join(c.evidence) if c.evidence else "",
            }
            for c in result.checks
        ]
    )
    st.dataframe(checks_df, width="stretch", hide_index=True)

    with st.expander("Full text report"):
        st.code(result.report(), language=None)


st.title("🛡️ Phishing Email Triage")
st.caption("Upload a `.eml` file to analyze phishing indicators.")

with st.sidebar:
    st.header("Options")
    enable_whois = st.checkbox("Enable WHOIS lookups", value=True, help="Slower, but checks domain age.")
    org_domains_raw = st.text_input(
        "Organization domains",
        placeholder="example.com, example.org",
        help="Comma-separated domains you trust as internal.",
    )
    org_domains = [d.strip() for d in org_domains_raw.split(",") if d.strip()]

uploaded = st.file_uploader("Upload email (.eml)", type=["eml"])

if uploaded is not None:
    with st.spinner("Analyzing email…"):
        result = analyze_bytes(
            uploaded.getvalue(),
            filename=uploaded.name,
            org_domains=org_domains or None,
            enable_whois=enable_whois,
        )
    render_result(result)
else:
    st.info("Choose an `.eml` file to get started.")
