# 🛡️ Cybersecurity Internship Report – Task 2

**Intern Name:** Kondiba Gangadhar Jogdand  
**Organization:** Elevate Labs  
**Task Title:** Phishing Email Investigation  
**Date Completed:** August 5, 2025  

---

## 📈 Objective

To investigate a suspicious email containing a potentially malicious link using manual inspection and cybersecurity tools. The goal is to understand the anatomy of phishing attacks and analyze threat indicators.

---

## 🔧 Tools Used

| Tool         | Purpose                              |
| ------------ | ------------------------------------ |
| Browser (View Source) | Manual inspection of email content |
| VirusTotal   | Scan links & attachments for malware |
| URLScan.io   | DNS and reputation check             |
| WHOIS        | Domain registration information      |
| DomainTools  | Threat history and blacklisting info |

---

## 📨 Step-by-Step Investigation

### ✅ 1. Email Received

The email was structured in HTML format (`testmail.html`) and included a suspicious login link to:

```
http://mycloud-security-center.net/login-auth/session-id=8h3d9s0a
```

---

### 🔍 2. Manual HTML Inspection

**Actions:** Opened the file in a browser and text editor.  
**Findings:**

- Link displayed to look like a Microsoft Security alert.
- Hovering over the link showed mismatch domain.
- HTML code used `href` tag for redirect and looked deceptively clean.

---

### 🛑 3. Link Analysis via VirusTotal

- **Link Scanned:** `http://mycloud-security-center.net/login-auth/session-id=8h3d9s0a`
- **Result:** 0/97 engines flagged it as malicious
- **Observation:** The link might be newly generated or inactive.

🖼 Screenshot: `virustotal_result.png`

---

### 🌐 4. DNS & IP Analysis (URLScan.io)

- Result: **DNS Error – Could not resolve domain**
- Indicates the domain is either taken down or never existed

🖼 Screenshot: `urlscan_dns_error.png`

---

### 🌎 5. WHOIS Lookup

Performed WHOIS query using online tools:

- **Domain:** `mycloud-security-center.net`
- **Status:** No registration data found.
- **Conclusion:** Possibly generated for one-time phishing.

---

### 🧠 6. Red Flags Identified

| Red Flag                        | Description                                      |
| ------------------------------ | ------------------------------------------------ |
| Fake Domain Name               | Not a Microsoft-owned domain                     |
| URL Mismatch                   | Visible vs. actual link differs                  |
| Suspicious URL Path            | Contains fake session ID and path                |
| No Registration/DNS Found      | May be expired, unregistered, or sinkholed       |
| HTML Email with Urgency Theme  | Classic sign of phishing                         |

---

## 🗂 GitHub Directory Structure

```
Task-2-Phishing-Investigation/
├── testmail.html
├── virustotal_result.png
├── urlscan_dns_error.png
├── phishing_analysis_report.md
└── README.md
```

---

## 🧾 Outcome

- Understood key traits of phishing emails
- Practiced use of live cybersecurity threat intelligence tools
- Identified and documented multiple threat indicators

---

## 🎓 Key Concepts Learned

- Phishing link analysis
- Email HTML inspection
- VirusTotal and URL reputation tools
- WHOIS & DNS recon
- Reporting and red flag identification

---

**Submitted on:** August 5, 2025  
**GitHub Repo:** [https://github.com/cptjkcyber/task-2-phishing-investigation](https://github.com/cptjkcyber/task-2-phishing-investigation)