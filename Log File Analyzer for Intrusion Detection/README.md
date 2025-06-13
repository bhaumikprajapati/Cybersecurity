# 🔍 LOG FILE ANALYZER FOR INTRUSION DETECTION

A **Python-based cybersecurity tool** that analyzes system log files to detect and report potential security threats, such as brute-force SSH attacks and HTTP DoS or scanning behavior.  
Developed as part of a cybersecurity internship project.

---

## ✅ FEATURES

- 🚨 Brute-force Attack Detection (SSH logs)
- 🌐 DoS / Scanning Detection (Apache logs)
- 🔄 Correlation of threats across logs
- 📊 Graphical Report using matplotlib
- 📁 Exports to `.csv` and `.txt` files

---

## 🗂️ PROJECT STRUCTURE

```
Log File Analyzer/
├── main.py                  -> Core script
├── apache_test.log          -> Sample Apache log file
├── ssh_test.log             -> Sample SSH log file
├── brute_force_ips.csv      -> Exported suspicious SSH IPs
├── dos_suspicious_ips.csv   -> Exported Apache scanning IPs
├── correlated_ips.txt       -> Common attackers across both logs
```

---

## ⚙️ SETUP INSTRUCTIONS

### 1. Install Python (3.9 or above)

### 2. (Optional) Create a Virtual Environment

#### On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

#### On Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Required Packages

```bash
pip install pandas matplotlib
```

### 4. Run the Project

```bash
python main.py
```

---

## 🧪 SAMPLE OUTPUT

- SSH Log Analysis: Detects brute-force attempts and reports IPs with repeated failed logins.
- Apache Log Analysis: Identifies IPs with abnormal request volume.
- Correlated Threats: Flags IPs appearing in both SSH and Apache logs.
- Visualization: Line graph of HTTP request activity over time.

---

## 📊 GRAPH OUTPUT

**Example: Request Frequency (per IP per minute)**

```
192.168.1.101: [#####################]
192.168.1.105: [###]
```

(Generated using `matplotlib`)

---

## 👨‍💻 DEVELOPED BY

- **Internship**: Elevate Labs – Cybersecurity Domain  
- **Intern**: Bhaumik Prajapati  
- **Course**: B.Sc. (CA & IT), Ganpat University  

---

## ⚠️ DISCLAIMER

This tool is designed for **educational** and **internal auditing** purposes only.  
Do not analyze or share real-world logs containing personal or production data without proper authorization.

---
