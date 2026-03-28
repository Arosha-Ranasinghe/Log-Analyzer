/**
 * utils.js - CLI helpers
 */

function printBanner() {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║         🔍 Log Analyzer & Anomaly Detector               ║
║              Built with Node.js                          ║
╚══════════════════════════════════════════════════════════╝
`);
}

function printHelp() {
  console.log(`
USAGE:
  node index.js <logfile> [options]

OPTIONS:
  --json              Output report in JSON format
  --output <file>     Save report to a file instead of stdout
  -h, --help          Show this help message

EXAMPLES:
  node index.js access.log
  node index.js /var/log/auth.log --json
  node index.js access.log --output report.txt
  node index.js auth.log --json --output report.json

SUPPORTED LOG FORMATS:
  • Apache / Nginx combined access log
  • Syslog (auth.log, syslog)
  • Generic timestamped logs (ISO 8601)

DETECTS:
  • Brute force / credential stuffing attacks
  • SQL injection attempts
  • XSS attempts
  • Path traversal attacks
  • Known security scanner user agents
  • Off-hours suspicious activity
  • High request volume from single IPs
  • SSH invalid user attempts

⚠️  For educational and defensive security purposes only.
`);
}

module.exports = { printBanner, printHelp };
