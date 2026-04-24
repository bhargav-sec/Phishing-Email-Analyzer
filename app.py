"""
Phishing Email Analyzer — Streamlit Web UI
Now supports .txt, .eml, .msg, .pdf, and image uploads.

Author: Bhargav (bhargav-sec)
"""

import os
import json
import streamlit as st
from groq import Groq
from email_parser import parse_email_file, SUPPORTED_EXTENSIONS

# ---------- Page config ----------
st.set_page_config(
    page_title="Phishing Email Analyzer",
    page_icon="🎣",
    layout="wide",
)

# ---------- API setup ----------
API_KEY = os.environ.get("GROQ_API_KEY")
if not API_KEY:
    st.error("❌ GROQ_API_KEY environment variable not set.")
    st.stop()

client = Groq(api_key=API_KEY)
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """You are a Tier-2 SOC analyst with expertise in phishing analysis and MITRE ATT&CK.
Analyze the email the user sends and return a STRICT JSON response with these exact keys:

{
  "verdict": "PHISHING | SUSPICIOUS | LEGITIMATE",
  "confidence": "HIGH | MEDIUM | LOW",
  "intent": "credential_theft | malware_delivery | bec_fraud | reconnaissance | other",
  "summary": "2-3 sentence executive summary",
  "red_flags": ["list", "of", "indicators"],
  "iocs": {
    "urls": [],
    "domains": [],
    "ip_addresses": [],
    "email_addresses": [],
    "file_hashes": [],
    "attachments": []
  },
  "mitre_attack": [
    {"tactic": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing"}
  ],
  "recommended_actions": ["list", "of", "soc", "actions"]
}

Return ONLY valid JSON. Do not include markdown fences."""


def analyze_email(email_content: str) -> dict:
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"EMAIL TO ANALYZE:\n---\n{email_content}\n---"},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": str(e)}


# ---------- UI ----------
st.title("🎣 Phishing Email Analyzer")
st.caption("AI-powered SOC triage tool • Powered by Groq (Llama 3.3 70B) • Built by Bhargav")

with st.sidebar:
    st.header("ℹ️ About")
    st.markdown(
        """
        Upload any suspicious email and this tool will:
        - Classify it (PHISHING / SUSPICIOUS / LEGITIMATE)
        - Extract IOCs (URLs, domains, IPs, hashes)
        - Map tactics to **MITRE ATT&CK**
        - Recommend SOC actions
        
        **Supports:** `.txt`, `.eml`, `.msg`, `.pdf`, `.png`, `.jpg`
        """
    )
    st.divider()
    st.markdown("**Tech:** Python · Groq API · Streamlit · Tesseract OCR · pdfplumber")
    st.markdown("[GitHub Repo](https://github.com/bhargav-sec/Phishing-Email-Analyzer)")

# ---------- Input tabs ----------
st.subheader("📥 Input")

tab_upload, tab_paste, tab_samples = st.tabs([
    "📎 Upload File",
    "📝 Paste Text",
    "🗂️ Load Sample",
])

email_text = ""

with tab_upload:
    uploaded = st.file_uploader(
        "Drag & drop or browse — PDF, EML, MSG, TXT, or screenshot",
        type=SUPPORTED_EXTENSIONS,
        accept_multiple_files=False,
    )
    if uploaded is not None:
        try:
            with st.spinner(f"📄 Extracting text from {uploaded.name}..."):
                email_text = parse_email_file(uploaded.name, uploaded.getvalue())
            st.success(f"✅ Extracted {len(email_text)} characters from `{uploaded.name}`")
            with st.expander("Preview extracted text"):
                st.text(email_text[:2000] + ("..." if len(email_text) > 2000 else ""))
        except Exception as e:
            st.error(f"❌ Could not parse file: {e}")

with tab_paste:
    pasted = st.text_area(
        "Paste raw email (headers + body):",
        height=280,
        placeholder="From: ...\nTo: ...\nSubject: ...\n\n<body>",
    )
    if pasted.strip():
        email_text = pasted

with tab_samples:
    samples_dir = "samples"
    sample_files = []
    if os.path.isdir(samples_dir):
        sample_files = sorted(
            [f for f in os.listdir(samples_dir) if f.endswith(".txt")]
        )
    selected = st.selectbox(
        "Load a sample email",
        ["-- none --"] + sample_files,
    )
    if selected != "-- none --":
        with open(os.path.join(samples_dir, selected), "r", encoding="utf-8") as f:
            email_text = f.read()
        with st.expander("Preview sample"):
            st.text(email_text)

analyze_btn = st.button("🔍 Analyze Email", type="primary", use_container_width=True)

# ---------- Analysis output ----------
if analyze_btn:
    if not email_text.strip():
        st.warning("Please upload, paste, or select an email first.")
        st.stop()

    with st.spinner("🧠 Analyzing email with AI..."):
        result = analyze_email(email_text)

    if "error" in result:
        st.error(f"Error: {result['error']}")
        st.stop()

    verdict = result.get("verdict", "UNKNOWN")
    confidence = result.get("confidence", "N/A")
    intent = result.get("intent", "N/A")

    verdict_colors = {
        "PHISHING": ("🚨", "red"),
        "SUSPICIOUS": ("⚠️", "orange"),
        "LEGITIMATE": ("✅", "green"),
    }
    icon, color = verdict_colors.get(verdict, ("❓", "gray"))

    st.markdown(f"### {icon} Verdict: :{color}[**{verdict}**]")

    m1, m2, m3 = st.columns(3)
    m1.metric("Confidence", confidence)
    m2.metric("Intent", intent)
    m3.metric("Red Flags", len(result.get("red_flags", [])))

    st.divider()

    st.subheader("📄 Executive Summary")
    st.info(result.get("summary", "N/A"))

    left, right = st.columns(2)

    with left:
        st.subheader("🚩 Red Flags")
        for flag in result.get("red_flags", []):
            st.markdown(f"- {flag}")

        st.subheader("✅ Recommended SOC Actions")
        for a in result.get("recommended_actions", []):
            st.markdown(f"- {a}")

    with right:
        st.subheader("🧾 Indicators of Compromise (IOCs)")
        iocs = result.get("iocs", {})
        any_iocs = False
        for key, values in iocs.items():
            if values:
                any_iocs = True
                with st.expander(f"{key} ({len(values)})", expanded=True):
                    for v in values:
                        st.code(v, language=None)
        if not any_iocs:
            st.caption("No IOCs extracted.")

        st.subheader("🛡️ MITRE ATT&CK Mapping")
        for t in result.get("mitre_attack", []):
            st.markdown(
                f"- **{t.get('tactic')}** → "
                f"`{t.get('technique_id')}` ({t.get('technique_name')})"
            )

    with st.expander("🔧 Raw JSON (for SOAR integration)"):
        st.json(result)