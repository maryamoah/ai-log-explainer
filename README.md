
![Python Version](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/github/license/maryamoah/ai-log-explainer)
![Last Commit](https://img.shields.io/github/last-commit/maryamoah/ai-log-explainer)
![Repo Size](https://img.shields.io/github/repo-size/maryamoah/ai-log-explainer)
![Issues](https://img.shields.io/github/issues/maryamoah/ai-log-explainer)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapping%20Enabled-orange)

# AI Log Explainer  
*Explainable Security Log Analysis with IOC Extraction and MITRE ATT&CK Mapping*

This project demonstrates a hybrid **research + engineering** approach for automated log interpretation in Security Operations Centers (SOC).  
It parses security logs (FortiSIEM-style, F5 WAF, Trend Micro CEF), extracts Indicators of Compromise (IOCs), maps events to **MITRE ATT&CK** techniques, and generates human-friendly explanation text.

The tool is fully offline, modular, and ideal for:
- SOC automation research  
- Explainable AI in cybersecurity  
- PhD applications  
- Log analysis prototyping  
- Threat intelligence enrichment  

---

## 📘 Key Features

### 🔹 Multi-Vendor Log Parsing  
Supports:
- Palo Alto THREAT logs (forwarded to FortiSIEM)
- F5 WAF attack logs
- Trend Micro Apex Central CEF logs

### 🔹 IOC Extraction  
Automatically extracts:
- IPv4 addresses  
- Domains  
- Email addresses  
- Hashes (MD5/SHA1/SHA256)

### 🔹 MITRE ATT&CK Technique Mapping  
Rule-based mapping from:
- Threat categories  
- Action fields  
- Protocols  
- Keywords  

Example techniques triggered:
- **T1046 — Network Service Scanning**  
- **T1071 — Application Layer Protocol**  
- **T1190 — Exploit Public-Facing Application**  

### 🔹 Explainable AI Output  
LLM-style narrative generation without external API calls.

### 🔹 JSON or Rich Console Output  
Machine-readable for automation, or human-readable for analysts.

---

## 🏗 Architecture Overview

```
 Raw Log File
      │
      ▼
┌──────────────────────────┐
│     Parser Layer         │
│  (FortiSIEM / F5 / TM)   │
└─────────────┬────────────┘
              ▼
┌──────────────────────────┐
│      IOC Extractor        │
│   (IP, domain, hash)      │
└─────────────┬────────────┘
              ▼
┌──────────────────────────┐
│     MITRE Mapper         │
│  (Keyword + heuristics)  │
└─────────────┬────────────┘
              ▼
┌──────────────────────────┐
│  Explanation Generator   │
│    (LLM-style text)      │
└─────────────┬────────────┘
              ▼
   Human Output / JSON
```

---

## 🚀 Installation

```bash
git clone https://github.com/maryamoah/ai-log-explainer.git
cd ai-log-explainer
python -m venv venv
source venv/Scripts/activate   # Windows
pip install -r requirements.txt
```

---

## ▶️ Usage

### Human-readable output:

```bash
python src/main.py --file examples/fortisiem.log --parser fortisiem
```

### JSON output:

```bash
python src/main.py --file examples/f5_waf.log --parser f5_waf --json
```

---

## 🧪 Example Output

```
Timestamp   : 2025/11/24 01:33:21
Source IP   : 172.31.141.240
Destination : 88.119.174.113
Category    : Non-RFC Compliant NTP Traffic on Port 123(56473)

Indicators:
 - ip: 172.31.141.240
 - ip: 88.119.174.113
 - domain: edu.om

MITRE ATT&CK:
 - T1046 Network Service Scanning
 - T1071 Application Layer Protocol

Explanation:
 This log entry describes 'Non-RFC Compliant NTP Traffic…'
 Observed indicators include…
 The behaviour aligns with MITRE…
```

---

## 🧠 Research Context

This project explores:
- Explainable AI in cybersecurity  
- Automated log interpretation  
- Heuristic-driven ATT&CK labeling  
- SOC decision-support tooling  
- Cross-vendor normalization of threat logs  

Future research directions:
- Embedding-based similarity detection  
- Pattern clustering and anomaly detection  
- Integration with local LLMs (Ollama / GPT4All)  
- ATT&CK sub-techniques enrichment  
- Analyst-in-the-loop evaluation  

---

## 📌 Roadmap

- [ ] Auto-detect log source (no need for `--parser`)  
- [ ] Add phishing/email logs  
- [ ] Add Sysmon + EDR sample logs  
- [ ] Implement Ollama LLM integration  
- [ ] Add anomaly scoring module  
- [ ] Add Docker image CI build  
- [ ] Provide Jupyter research notebook  

---

## 📝 License  
MIT License.

---

## ⭐ Acknowledgements  
Developed as part of a Security Operations research portfolio to demonstrate explainable analytics and SOC automation techniques.
