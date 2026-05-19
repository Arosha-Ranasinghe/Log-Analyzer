# 🔍 Log Analyzer & Anomaly Detector

A powerful, zero-dependency Node.js tool that parses server logs and detects security anomalies - brute force attacks, SQL injections, XSS attempts, path traversals, and more.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔴 Brute Force Detection | Flags IPs with repeated failed logins |
| 💉 SQL Injection Detection | Catches UNION, SELECT, DROP and more in URLs |
| ⚡ XSS Detection | Detects `<script>`, `onerror=`, `alert()` patterns |
| 📂 Path Traversal Detection | Catches `../../` style attacks |
| 🤖 Scanner Detection | Identifies Nikto, sqlmap, Nmap, Gobuster, etc. |
| 🕐 Off-Hours Activity | Flags suspicious traffic between midnight and 5 AM |
| 📊 HTTP Stats | Status codes, methods, top IPs, top endpoints |
| 🔐 SSH Analysis | Failed logins, accepted logins, invalid users |
| 📝 JSON Export | Full structured output for SIEM integration |

---

## 📋 Requirements

- Node.js v14+
- No external dependencies (100% built-in modules)

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
```

No `npm install` needed — zero dependencies!

---

## 💻 Usage

```bash
# Analyze an Apache/Nginx access log
node index.js samples/access.log

# Analyze a Linux auth/syslog file
node index.js samples/auth.log

# Output as JSON
node index.js access.log --json

# Save report to file
node index.js access.log --output report.txt

# Save JSON report to file
node index.js access.log --json --output report.json

# Show help
node index.js --help
```

### npm scripts (quick testing)
```bash
npm run test:access   # Test with sample access log
npm run test:auth     # Test with sample auth log
npm run test:json     # Test JSON output
```

---

## 📁 Project Structure

```
log-analyzer/
├── index.js            # CLI entry point
├── package.json
├── src/
│   ├── analyzer.js     # Core detection engine
│   ├── reporter.js     # Output formatting (text + JSON)
│   └── utils.js        # CLI banner and help
├── samples/
│   ├── access.log      # Sample Apache access log
│   └── auth.log        # Sample Linux auth log
└── README.md
```

---

## 📊 Example Output

```
╔══════════════════════════════════════════════════════════╗
║         🔍 Log Analyzer & Anomaly Detector               ║
╚══════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════
  📋  LOG ANALYSIS REPORT
════════════════════════════════════════════════════════════

📊 SUMMARY
────────────────────────────────────────────────────────────
  Total Lines   : 30
  Parsed Lines  : 30
  Skipped Lines : 0

🚨 ANOMALIES DETECTED
────────────────────────────────────────────────────────────
  Found 5 anomaly/anomalies:

  1. 🟠 [HIGH] SQL_INJECTION_ATTEMPT
     1 SQL injection attempt(s) detected
     IP: 172.16.0.5

  2. 🟠 [HIGH] XSS_ATTEMPT
     1 XSS attempt(s) detected
     IP: 172.16.0.5

  3. 🟠 [HIGH] PATH_TRAVERSAL
     1 path traversal attempt(s) detected
     IP: 172.16.0.5

  4. 🟡 [MEDIUM] BRUTE_FORCE
     10 failed login/error attempts from 10.0.0.1

  5. 🔵 [LOW] OFF_HOURS_ACTIVITY
     3 events detected between midnight and 5 AM
```

---

## 🛡️ Supported Log Formats

- **Apache / Nginx** Combined Log Format
- **Syslog** (`/var/log/auth.log`, `/var/log/syslog`)
- **Generic** ISO 8601 timestamped logs (`YYYY-MM-DD HH:MM:SS LEVEL message`)

---

## 🔮 Future Ideas

- [ ] Real-time log watching (`--watch` mode)
- [ ] Email/Slack alerts
- [ ] IP geolocation lookup
- [ ] Custom rule configuration (JSON rules file)
- [ ] HTML report generation
- [ ] Whitelist/blacklist support

---

## ⚠️ Legal Disclaimer

This tool is intended for **defensive security**, log analysis, and educational purposes only. Only use it on systems you own or have explicit permission to analyze.

