"""
Phishing Email Analyzer
AI-powered tool that analyzes phishing emails, extracts IOCs,
classifies intent, and maps tactics to MITRE ATT&CK.

Author: Bhargav (bhargav-sec)
"""

import os
import sys
import json
from groq import Groq

API_KEY = os.environ.get("GROQ_API_KEY")
if not API_KEY:
    print("❌ ERROR: GROQ_API_KEY environment variable not set.")
    sys.exit(1)

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
    """Send email to Groq and return parsed JSON analysis."""
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
        text = response.choices[0].message.content
        return json.loads(text)
    except json.JSONDecodeError as e:
        return {"error": f"Model did not return valid JSON: {e}"}
    except Exception as e:
        return {"error": str(e)}


def print_report(result: dict) -> None:
    """Pretty-print the analysis as a SOC report."""
    if "error" in result:
        print(f"\n❌ Error: {result['error']}")
        return

    verdict_icons = {"PHISHING": "🚨", "SUSPICIOUS": "⚠️", "LEGITIMATE": "✅"}
    icon = verdict_icons.get(result.get("verdict", ""), "❓")

    print("\n" + "=" * 60)
    print(f"  {icon}  PHISHING EMAIL ANALYSIS REPORT")
    print("=" * 60)
    print(f"\n🔎 Verdict:    {result.get('verdict')} ({result.get('confidence')} confidence)")
    print(f"🎯 Intent:     {result.get('intent')}")
    print(f"\n📄 Summary:\n   {result.get('summary')}")

    print("\n🚩 Red Flags:")
    for flag in result.get("red_flags", []):
        print(f"   • {flag}")

    print("\n🧾 Indicators of Compromise (IOCs):")
    iocs = result.get("iocs", {})
    for key, values in iocs.items():
        if values:
            print(f"   {key}:")
            for v in values:
                print(f"      - {v}")

    print("\n🛡️  MITRE ATT&CK Mapping:")
    for t in result.get("mitre_attack", []):
        print(f"   • {t.get('tactic')} → {t.get('technique_id')} ({t.get('technique_name')})")

    print("\n✅ Recommended SOC Actions:")
    for a in result.get("recommended_actions", []):
        print(f"   • {a}")
    print("\n" + "=" * 60 + "\n")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path-to-email-file.txt>")
        print("Example: python analyzer.py samples/sample1.txt")
        sys.exit(1)

    email_path = sys.argv[1]
    if not os.path.exists(email_path):
        print(f"❌ File not found: {email_path}")
        sys.exit(1)

    with open(email_path, "r", encoding="utf-8", errors="ignore") as f:
        email_content = f.read()

    print(f"📧 Analyzing: {email_path} ...")
    result = analyze_email(email_content)
    print_report(result)


if __name__ == "__main__":
    main()