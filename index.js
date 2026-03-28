#!/usr/bin/env node



const fs = require("fs");
const path = require("path");
const { analyzeLog } = require("./src/analyzer");
const { generateReport } = require("./src/reporter");
const { printBanner, printHelp } = require("./src/utils");

async function main() {
  printBanner();

  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  const logFile = args[0];
  const outputFormat = args.includes("--json") ? "json" : "text";
const outputIndex = args.indexOf("--output");
const outputFile = outputIndex !== -1 ? args[outputIndex + 1] : null;

  // Validate file exists
  if (!fs.existsSync(logFile)) {
    console.error(`❌ Error: File not found: ${logFile}`);
    process.exit(1);
  }

  const ext = path.extname(logFile).toLowerCase();
  const supportedExts = [".log", ".txt", ".csv", ""];
  if (!supportedExts.includes(ext)) {
    console.warn(`⚠️  Warning: Unrecognized file extension "${ext}". Attempting to parse anyway...`);
  }

  console.log(`\n📂 Loading log file: ${logFile}`);
  console.log(`📊 Output format   : ${outputFormat}`);
  if (outputFile) console.log(`💾 Saving report to: ${outputFile}`);
  console.log("");

  try {
    const results = await analyzeLog(logFile);
    const report = generateReport(results, outputFormat);

    if (outputFile) {
      fs.writeFileSync(outputFile, report, "utf8");
      console.log(`\n✅ Report saved to: ${outputFile}`);
    } else {
      console.log(report);
    }
  } catch (err) {
    console.error("❌ Error during analysis:", err.message);
    process.exit(1);
  }
}

main();
