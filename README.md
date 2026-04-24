# 🎣 Phishing Email Analyzer

AI-powered phishing email analyzer that extracts IOCs, classifies intent, and maps attack tactics to MITRE ATT&CK — built for SOC analysts.

Accepts any email format (paste, upload PDF/EML/MSG, or drop a screenshot) and returns a Tier-2 SOC report in under 5 seconds using an LLM.

---

## 🔍 What it does

Feed it a suspicious email (any format) and get a structured SOC report:

- **Verdict** — PHISHING / SUSPICIOUS / LEGITIMATE with confidence level
- **Intent classification** — credential theft, malware delivery, BEC fraud, etc.
- **Red flags** — specific social engineering and technical indicators
- **IOCs** — URLs, domains, IPs, email addresses, file hashes, attachments
- **MITRE ATT&CK mapping** — tactic → technique ID → technique name
- **Recommended SOC actions** — containment and remediation steps

---

## 📥 Supported input formats

| Format | Description | Used for |
|---|---|---|
| `.txt` | Plain text | Copy-pasted emails |
| `.eml` | Standard email file | Gmail / Thunderbird exports |
| `.msg` | Outlook email file | Microsoft Outlook exports |
| `.pdf` | Printed / saved email | PDFs of emails |
| `.png` / `.jpg` | Screenshot of an email | Phone or desktop screenshots (OCR) |

---

## 🧪 Example output

```
🚨  PHISHING EMAIL ANALYSIS REPORT
============================================================
🔎 Verdict:    PHISHING (HIGH confidence)
🎯 Intent:     credential_theft

📄 Summary:
   The email claims to be from Microsoft Security, warning of unusual
   sign-in activity and threatening account suspension unless the user
   verifies their identity via a suspicious link.

🚩 Red Flags:
   • Typosquat sender domain (micros0ft-security.com)
   • Reply-To domain mismatch
   • Urgency and account suspension threats
   • Suspicious HTML attachment

🧾 IOCs:
   domains:      micros0ft-security.com, micros0ft-verify.net
   ip_addresses: 185.220.101.47 (Tor exit node)
   attachments:  account_verification.html

🛡️  MITRE ATT&CK:
   • Initial Access → T1566 (Phishing)

✅ Recommended SOC Actions:
   • Block sender domain at email gateway
   • Add URL/IP to proxy blocklist
   • Hunt for users who clicked the link
   • Report to IR team and kick off user awareness
```

---

## 🛠️ Tech stack

- **Python 3.12**
- **Groq API** — Llama 3.3 70B for structured JSON output
- **Streamlit** — interactive web UI
- **pdfplumber** — PDF text extraction
- **extract-msg** — Outlook `.msg` parsing
- **Pillow + pytesseract** — OCR for image / screenshot emails
- **Prompt engineering** — role-based system prompt (Tier-2 SOC analyst)
- **MITRE ATT&CK framework** — tactic and technique mapping

---

## ⚙️ Setup

### Prerequisites
- Python 3.10+
- Free Groq API key from [console.groq.com](https://console.groq.com/keys)
- Tesseract OCR engine (for image input): `sudo apt-get install tesseract-ocr`

### Install

```bash
git clone https://github.com/bhargav-sec/Phishing-Email-Analyzer.git
cd Phishing-Email-Analyzer
pip install -r requirements.txt
```

### Configure

```bash
export GROQ_API_KEY="gsk_your_key_here"
```

### Run (CLI)

```bash
python analyzer.py samples/sample1.txt
```

### Run (Web UI)

```bash
streamlit run app.py
```

Opens an interactive dashboard with three input modes: file upload, paste, or load from sample library.

---

## 📁 Project structure

```
Phishing-Email-Analyzer/
├── analyzer.py          # CLI analyzer
├── app.py               # Streamlit web UI
├── email_parser.py      # Multi-format file parser (.eml/.msg/.pdf/images)
├── requirements.txt     # Python dependencies
├── samples/             # Example phishing & legitimate emails
│   ├── sample1.txt         # Microsoft credential theft
│   ├── sample2_bec.txt     # CEO fraud / BEC
│   ├── sample3_malware.txt # DHL malware delivery
│   └── sample4_legitimate.txt # Legitimate GitHub notification
└── README.md
```

---

## 🎯 Why I built this

SOC analysts triage hundreds of phishing reports per week. This tool:
- Cuts analysis time from ~10 min to ~5 sec per email
- Produces consistent, structured JSON output ready for SOAR / ticketing systems
- Maps automatically to the MITRE ATT&CK framework
- Demonstrates how LLMs can augment (not replace) Tier-1 SOC triage work

---

## 🚧 Roadmap

- [x] Streamlit web UI
- [x] Multi-format input (PDF, EML, MSG, image OCR)
- [ ] VirusTotal / AbuseIPDB enrichment for extracted IOCs
- [ ] Batch analysis from a folder of mixed email formats
- [ ] Export reports as PDF / JSON for SOAR integration
- [ ] Benchmark accuracy on a labelled phishing dataset

---

## 👤 Author

**Bhargav Chowdary** — Cybersecurity Analyst, Dublin 🇮🇪  
SOC · SIEM · Threat Detection · Blue Team  
[LinkedIn](https://www.linkedin.com/in/bhargav-chowdary-cybersecurity/) · [GitHub](https://github.com/bhargav-sec)