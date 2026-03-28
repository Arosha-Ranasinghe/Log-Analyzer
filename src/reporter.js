/**
 * reporter.js - Formats analysis results into readable reports
 */

const SEVERITY_ICONS = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🔵",
};

function generateReport(results, format = "text") {
  if (format === "json") {
    return JSON.stringify(results, null, 2);
  }
  return generateTextReport(results);
}

function generateTextReport({ stats, counters, events, anomalies }) {
  const lines = [];

  const hr = (char = "─", len = 60) => char.repeat(len);

  // ── Header ──────────────────────────────────────────────────────────────────
  lines.push(hr("═"));
  lines.push("  📋  LOG ANALYSIS REPORT");
  lines.push(hr("═"));

  // ── Summary ─────────────────────────────────────────────────────────────────
  lines.push("\n📊 SUMMARY");
  lines.push(hr());
  lines.push(`  Total Lines   : ${stats.totalLines}`);
  lines.push(`  Parsed Lines  : ${stats.parsedLines}`);
  lines.push(`  Skipped Lines : ${stats.skippedLines}`);
  if (stats.startTime) lines.push(`  Log Start     : ${stats.startTime}`);
  if (stats.endTime)   lines.push(`  Log End       : ${stats.endTime}`);

  // ── Anomalies ────────────────────────────────────────────────────────────────
  lines.push("\n🚨 ANOMALIES DETECTED");
  lines.push(hr());

  if (anomalies.length === 0) {
    lines.push("  ✅ No anomalies detected.");
  } else {
    lines.push(`  Found ${anomalies.length} anomaly/anomalies:\n`);
    anomalies.forEach((a, i) => {
      const icon = SEVERITY_ICONS[a.severity] || "⚪";
      lines.push(`  ${i + 1}. ${icon} [${a.severity}] ${a.type}`);
      lines.push(`     ${a.detail}`);
      if (a.ip) lines.push(`     IP: ${a.ip}`);
      lines.push("");
    });
  }

  // ── HTTP Stats ───────────────────────────────────────────────────────────────
  if (Object.keys(counters.statusCodes).length > 0) {
    lines.push("📡 HTTP STATUS CODES");
    lines.push(hr());
    const sorted = Object.entries(counters.statusCodes).sort((a, b) => b[1] - a[1]);
    sorted.forEach(([code, count]) => {
      const bar = "█".repeat(Math.min(Math.ceil(count / 5), 30));
      lines.push(`  ${code}  ${bar} ${count}`);
    });
    lines.push("");
  }

  // ── HTTP Methods ─────────────────────────────────────────────────────────────
  if (Object.keys(counters.httpMethods).length > 0) {
    lines.push("🔧 HTTP METHODS");
    lines.push(hr());
    Object.entries(counters.httpMethods)
      .sort((a, b) => b[1] - a[1])
      .forEach(([method, count]) => {
        lines.push(`  ${method.padEnd(8)} : ${count}`);
      });
    lines.push("");
  }

  // ── Top IPs ──────────────────────────────────────────────────────────────────
  if (Object.keys(counters.ipRequests).length > 0) {
    lines.push("🌐 TOP 10 IPs BY REQUEST COUNT");
    lines.push(hr());
    Object.entries(counters.ipRequests)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([ip, count], i) => {
        lines.push(`  ${String(i + 1).padStart(2)}. ${ip.padEnd(18)} ${count} requests`);
      });
    lines.push("");
  }

  // ── Top Endpoints ────────────────────────────────────────────────────────────
  if (Object.keys(counters.topEndpoints).length > 0) {
    lines.push("🔗 TOP 10 ENDPOINTS");
    lines.push(hr());
    Object.entries(counters.topEndpoints)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([endpoint, count], i) => {
        const ep = endpoint.length > 40 ? endpoint.slice(0, 37) + "..." : endpoint;
        lines.push(`  ${String(i + 1).padStart(2)}. ${ep.padEnd(42)} ${count}`);
      });
    lines.push("");
  }

  // ── Log Levels ───────────────────────────────────────────────────────────────
  if (Object.keys(counters.logLevels).length > 0) {
    lines.push("📝 LOG LEVELS");
    lines.push(hr());
    Object.entries(counters.logLevels)
      .sort((a, b) => b[1] - a[1])
      .forEach(([level, count]) => {
        lines.push(`  ${level.padEnd(10)} : ${count}`);
      });
    lines.push("");
  }

  // ── Hourly Activity ───────────────────────────────────────────────────────────
  const hasHourlyData = counters.hourlyActivity.some((v) => v > 0);
  if (hasHourlyData) {
    lines.push("⏰ HOURLY ACTIVITY");
    lines.push(hr());
    const max = Math.max(...counters.hourlyActivity, 1);
    counters.hourlyActivity.forEach((count, hour) => {
      const barLen = Math.round((count / max) * 25);
      const bar = "█".repeat(barLen).padEnd(25);
      const label = `${String(hour).padStart(2)}:00`;
      lines.push(`  ${label}  ${bar} ${count}`);
    });
    lines.push("");
  }

  // ── SSH Events ────────────────────────────────────────────────────────────────
  if (events.sshFailures.length > 0 || events.sshSuccesses.length > 0) {
    lines.push("🔐 SSH EVENTS");
    lines.push(hr());
    lines.push(`  Failed logins   : ${events.sshFailures.length}`);
    lines.push(`  Successful logins: ${events.sshSuccesses.length}`);
    lines.push(`  Invalid users   : ${events.invalidUsers.length}`);

    if (events.sshFailures.length > 0) {
      lines.push("\n  Top SSH attacker IPs:");
      const ipCount = {};
      events.sshFailures.forEach(({ ip }) => {
        ipCount[ip] = (ipCount[ip] || 0) + 1;
      });
      Object.entries(ipCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .forEach(([ip, count]) => {
          lines.push(`    ${ip.padEnd(18)} ${count} attempts`);
        });
    }
    lines.push("");
  }

  // ── Attack Events ─────────────────────────────────────────────────────────────
  if (
    events.sqlInjections.length > 0 ||
    events.xssAttempts.length > 0 ||
    events.pathTraversals.length > 0 ||
    events.scannerDetections.length > 0
  ) {
    lines.push("⚔️  ATTACK EVENTS");
    lines.push(hr());
    if (events.sqlInjections.length > 0)
      lines.push(`  SQL Injection attempts  : ${events.sqlInjections.length}`);
    if (events.xssAttempts.length > 0)
      lines.push(`  XSS attempts            : ${events.xssAttempts.length}`);
    if (events.pathTraversals.length > 0)
      lines.push(`  Path traversal attempts : ${events.pathTraversals.length}`);
    if (events.scannerDetections.length > 0)
      lines.push(`  Scanner detections      : ${events.scannerDetections.length}`);
    lines.push("");
  }

  // ── Footer ────────────────────────────────────────────────────────────────────
  lines.push(hr("═"));
  lines.push(`  Generated: ${new Date().toISOString()}`);
  lines.push(hr("═"));

  return lines.join("\n");
}

module.exports = { generateReport };
