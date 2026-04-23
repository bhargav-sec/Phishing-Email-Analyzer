# 🎣 Phishing Email Analyzer

AI-powered phishing email analyzer that extracts IOCs, classifies intent, and maps attack tactics to MITRE ATT&CK — built for SOC analysts.

Built using Python and the Groq API (Llama 3.3 70B) to automate Tier-1 phishing triage in under 5 seconds per email.

---

## 🔍 What it does

Paste any suspicious email into a text file and the analyzer returns a structured SOC report:

- **Verdict** — PHISHING / SUSPICIOUS / LEGITIMATE with confidence level
- **Intent classification** — credential theft, malware delivery, BEC fraud, etc.
- **Red flags** — specific social engineering and technical indicators
- **IOCs** — URLs, domains, IPs, email addresses, file hashes, attachments
- **MITRE ATT&CK mapping** — tactic → technique ID → technique name
- **Recommended SOC actions** — containment and remediation steps

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
   domains:     micros0ft-security.com, micros0ft-verify.net
   ip_addresses: 185.220.101.47 (Tor exit node)
   attachments: account_verification.html

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
- **Prompt engineering** — role-based system prompt (SOC Tier-2 analyst)
- **MITRE ATT&CK framework** — mapping knowledge

---

## ⚙️ Setup

### Prerequisites
- Python 3.10+
- Free Groq API key from [console.groq.com](https://console.groq.com/keys)

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

### Run

```bash
python analyzer.py samples/sample1.txt
```

---

## 📁 Project structure

```
Phishing-Email-Analyzer/
├── analyzer.py          # Main analyzer
├── requirements.txt     # Python dependencies
├── samples/             # Example phishing emails
│   └── sample1.txt
└── README.md
```

---

## 🎯 Why I built this

SOC analysts triage hundreds of phishing reports per week. This tool:
- Cuts analysis time from ~10 min to ~5 sec per email
- Produces consistent, structured output for ticketing systems
- Maps automatically to the MITRE ATT&CK framework
- Demonstrates how LLMs can augment (not replace) Tier-1 SOC work

---

## 🚧 Roadmap

- [ ] Web UI (Streamlit)
- [ ] Batch analysis from a folder of `.eml` files
- [ ] VirusTotal / AbuseIPDB enrichment for IOCs
- [ ] Export reports as PDF/JSON for SOAR integration
- [ ] Support for reading raw `.eml` and `.msg` files

---

## 👤 Author

**Bhargav Chowdary** — Cybersecurity Analyst, Dublin 🇮🇪  
SOC · SIEM · Threat Detection · Blue Team  
[LinkedIn](https://www.linkedin.com/in/bhargav-chowdary-cybersecurity/) · [GitHub](https://github.com/bhargav-sec)
