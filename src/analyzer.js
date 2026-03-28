/**
 * analyzer.js - Core log analysis and anomaly detection engine
 */

const fs = require("fs");
const readline = require("readline");

// ── Regex Patterns ──────────────────────────────────────────────────────────

const PATTERNS = {
  // Apache / Nginx combined log format
  apacheCommon: /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-)/,

  // Syslog format
  syslog: /^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.+)/,

  // Generic timestamp + level + message
  generic: /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\w+)\s+(.+)/,

  // SSH brute force
  sshFailed: /Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)/,
  sshAccepted: /Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)/,
  sshInvalidUser: /Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)/,

  // HTTP patterns
  sqlInjection: /(\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bdelete\b|\bexec\b|--|\/\*|\*\/|xp_)/i,
  xssAttempt: /(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)/i,
  pathTraversal: /(\.\.[\/\\]){2,}/,
  scannerUA: /(nikto|nmap|sqlmap|masscan|zgrab|dirbuster|gobuster|wfuzz|hydra)/i,

  // Auth patterns
  authFailure: /(authentication failure|login failed|invalid credentials|wrong password)/i,
  authSuccess: /(authentication success|login successful|session opened)/i,

  // IP address
  ipAddress: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/,
};

// ── Thresholds ───────────────────────────────────────────────────────────────

const THRESHOLDS = {
  bruteForce: 10,         // failed logins from same IP
  portScan: 20,           // requests from same IP in short time
  errorSpike: 50,         // error count threshold
  rareHourActivity: true, // flag activity between 00:00 - 05:00
};

// ── Main Analyzer ────────────────────────────────────────────────────────────

async function analyzeLog(filePath) {
  const lines = await readLines(filePath);

  const stats = {
    totalLines: 0,
    parsedLines: 0,
    skippedLines: 0,
    startTime: null,
    endTime: null,
  };

  const counters = {
    httpMethods: {},
    statusCodes: {},
    logLevels: {},
    ipRequests: {},
    ipFailures: {},
    hourlyActivity: new Array(24).fill(0),
    topEndpoints: {},
    topUserAgents: {},
  };

  const anomalies = [];
  const events = {
    sshFailures: [],
    sshSuccesses: [],
    invalidUsers: [],
    sqlInjections: [],
    xssAttempts: [],
    pathTraversals: [],
    scannerDetections: [],
    authFailures: [],
    authSuccesses: [],
    httpErrors: [],
  };

  // ── Parse Each Line ────────────────────────────────────────────────────────
  for (const line of lines) {
    if (!line.trim()) continue;
    stats.totalLines++;

    let parsed = false;

    // Try Apache/Nginx format
    const apacheMatch = line.match(PATTERNS.apacheCommon);
    if (apacheMatch) {
      parsed = true;
      const [, ip, timestamp, method, endpoint, status, bytes] = apacheMatch;

      // Track IP
      counters.ipRequests[ip] = (counters.ipRequests[ip] || 0) + 1;

      // Track HTTP method
      counters.httpMethods[method] = (counters.httpMethods[method] || 0) + 1;

      // Track status codes
      counters.statusCodes[status] = (counters.statusCodes[status] || 0) + 1;

      // Track endpoints
      const cleanEndpoint = endpoint.split("?")[0];
      counters.topEndpoints[cleanEndpoint] = (counters.topEndpoints[cleanEndpoint] || 0) + 1;

      // Track failures per IP
      if (status.startsWith("4") || status.startsWith("5")) {
        counters.ipFailures[ip] = (counters.ipFailures[ip] || 0) + 1;
        events.httpErrors.push({ ip, timestamp, method, endpoint, status });
      }

      // Check for attacks
      if (PATTERNS.sqlInjection.test(endpoint)) {
        events.sqlInjections.push({ ip, timestamp, endpoint });
      }
      if (PATTERNS.xssAttempt.test(endpoint)) {
        events.xssAttempts.push({ ip, timestamp, endpoint });
      }
      if (PATTERNS.pathTraversal.test(endpoint)) {
        events.pathTraversals.push({ ip, timestamp, endpoint });
      }

      // Parse hour
      const hour = parseHour(timestamp);
      if (hour !== null) counters.hourlyActivity[hour]++;

      updateTimeRange(stats, timestamp);
    }

    // Try syslog format
    const syslogMatch = line.match(PATTERNS.syslog);
    if (!parsed && syslogMatch) {
      parsed = true;
      const [, timestamp, host, process_, message] = syslogMatch;

      // SSH patterns
      const sshFail = message.match(PATTERNS.sshFailed);
      if (sshFail) {
        events.sshFailures.push({ user: sshFail[1], ip: sshFail[2], timestamp });
        counters.ipFailures[sshFail[2]] = (counters.ipFailures[sshFail[2]] || 0) + 1;
      }

      const sshAccept = message.match(PATTERNS.sshAccepted);
      if (sshAccept) {
        events.sshSuccesses.push({ user: sshAccept[1], ip: sshAccept[2], timestamp });
      }

      const invalidUser = message.match(PATTERNS.sshInvalidUser);
      if (invalidUser) {
        events.invalidUsers.push({ user: invalidUser[1], ip: invalidUser[2], timestamp });
      }

      // Generic auth
      if (PATTERNS.authFailure.test(message)) {
        const ipMatch = message.match(PATTERNS.ipAddress);
        events.authFailures.push({ timestamp, message: message.slice(0, 100), ip: ipMatch ? ipMatch[1] : "unknown" });
      }
      if (PATTERNS.authSuccess.test(message)) {
        events.authSuccesses.push({ timestamp, message: message.slice(0, 100) });
      }

      const hour = parseHour(timestamp);
      if (hour !== null) counters.hourlyActivity[hour]++;
    }

    // Try generic format
    const genericMatch = line.match(PATTERNS.generic);
    if (!parsed && genericMatch) {
      parsed = true;
      const [, timestamp, level, message] = genericMatch;
      counters.logLevels[level.toUpperCase()] = (counters.logLevels[level.toUpperCase()] || 0) + 1;

      if (PATTERNS.authFailure.test(message)) {
        const ipMatch = message.match(PATTERNS.ipAddress);
        events.authFailures.push({ timestamp, message: message.slice(0, 100), ip: ipMatch ? ipMatch[1] : "unknown" });
      }

      const hour = parseHour(timestamp);
      if (hour !== null) counters.hourlyActivity[hour]++;
    }

    // Scanner user agent check (works across formats)
    if (PATTERNS.scannerUA.test(line)) {
      const ipMatch = line.match(PATTERNS.ipAddress);
      events.scannerDetections.push({
        ip: ipMatch ? ipMatch[1] : "unknown",
        line: line.slice(0, 120),
      });
    }

    if (parsed) {
      stats.parsedLines++;
    } else {
      stats.skippedLines++;
    }
  }

  // ── Anomaly Detection ──────────────────────────────────────────────────────

  // Brute force detection
  for (const [ip, count] of Object.entries(counters.ipFailures)) {
    if (count >= THRESHOLDS.bruteForce) {
      anomalies.push({
        type: "BRUTE_FORCE",
        severity: count >= 50 ? "CRITICAL" : count >= 20 ? "HIGH" : "MEDIUM",
        ip,
        detail: `${count} failed login/error attempts from ${ip}`,
        count,
      });
    }
  }

  // High request volume from single IP
  for (const [ip, count] of Object.entries(counters.ipRequests)) {
    if (count >= THRESHOLDS.portScan) {
      anomalies.push({
        type: "HIGH_REQUEST_VOLUME",
        severity: count >= 500 ? "HIGH" : "MEDIUM",
        ip,
        detail: `${count} requests from single IP ${ip}`,
        count,
      });
    }
  }

  // Error spike
  const totalErrors = Object.entries(counters.statusCodes)
    .filter(([code]) => code.startsWith("4") || code.startsWith("5"))
    .reduce((sum, [, count]) => sum + count, 0);

  if (totalErrors >= THRESHOLDS.errorSpike) {
    anomalies.push({
      type: "ERROR_SPIKE",
      severity: totalErrors >= 200 ? "HIGH" : "MEDIUM",
      ip: null,
      detail: `${totalErrors} total HTTP error responses detected`,
      count: totalErrors,
    });
  }

  // Attack detections
  if (events.sqlInjections.length > 0) {
    anomalies.push({
      type: "SQL_INJECTION_ATTEMPT",
      severity: "HIGH",
      ip: events.sqlInjections[0].ip,
      detail: `${events.sqlInjections.length} SQL injection attempt(s) detected`,
      count: events.sqlInjections.length,
    });
  }

  if (events.xssAttempts.length > 0) {
    anomalies.push({
      type: "XSS_ATTEMPT",
      severity: "HIGH",
      ip: events.xssAttempts[0].ip,
      detail: `${events.xssAttempts.length} XSS attempt(s) detected`,
      count: events.xssAttempts.length,
    });
  }

  if (events.pathTraversals.length > 0) {
    anomalies.push({
      type: "PATH_TRAVERSAL",
      severity: "HIGH",
      ip: events.pathTraversals[0].ip,
      detail: `${events.pathTraversals.length} path traversal attempt(s) detected`,
      count: events.pathTraversals.length,
    });
  }

  if (events.scannerDetections.length > 0) {
    anomalies.push({
      type: "SCANNER_DETECTED",
      severity: "HIGH",
      ip: events.scannerDetections[0].ip,
      detail: `Known security scanner user-agent detected (${events.scannerDetections.length} time(s))`,
      count: events.scannerDetections.length,
    });
  }

  if (events.invalidUsers.length > 0) {
    anomalies.push({
      type: "INVALID_SSH_USERS",
      severity: "MEDIUM",
      ip: events.invalidUsers[0].ip,
      detail: `${events.invalidUsers.length} SSH login attempt(s) with invalid usernames`,
      count: events.invalidUsers.length,
    });
  }

  // Night-time activity
  const nightActivity = counters.hourlyActivity.slice(0, 5).reduce((a, b) => a + b, 0);
  if (nightActivity > 20) {
    anomalies.push({
      type: "OFF_HOURS_ACTIVITY",
      severity: "LOW",
      ip: null,
      detail: `${nightActivity} events detected between midnight and 5 AM`,
      count: nightActivity,
    });
  }

  // Sort anomalies by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  anomalies.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return {
    stats,
    counters,
    events,
    anomalies,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function readLines(filePath) {
  return new Promise((resolve, reject) => {
    const lines = [];
    const rl = readline.createInterface({
      input: fs.createReadStream(filePath, { encoding: "utf8" }),
      crlfDelay: Infinity,
    });
    rl.on("line", (line) => lines.push(line));
    rl.on("close", () => resolve(lines));
    rl.on("error", reject);
  });
}

function parseHour(timestamp) {
  // Apache format: 10/Oct/2023:13:55:36
  const apacheHour = timestamp.match(/:(\d{2}):\d{2}:\d{2}/);
  if (apacheHour) return parseInt(apacheHour[1]);

  // ISO format: 2023-10-10T13:55:36
  const isoHour = timestamp.match(/T(\d{2}):/);
  if (isoHour) return parseInt(isoHour[1]);

  // Syslog: Oct 10 13:55:36
  const sysHour = timestamp.match(/\d+:(\d{2}):\d+/);
  if (sysHour) return parseInt(sysHour[0].split(":")[0]);

  return null;
}

function updateTimeRange(stats, timestamp) {
  if (!stats.startTime) stats.startTime = timestamp;
  stats.endTime = timestamp;
}

module.exports = { analyzeLog };
