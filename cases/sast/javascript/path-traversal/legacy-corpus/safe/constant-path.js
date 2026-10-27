// TG-PATH-SAFE-001, SAFE-011: paths built only from constants.
const fs = require("fs");

function readReport() {
  const filename = "/tmp/report.txt";
  return fs.readFileSync(filename); // TG-PATH-SAFE-001
}

function readSummary() {
  // Constant concatenation: every operand is a literal.
  const summaryPath = "/app/data" + "/" + "summary.txt";
  return fs.readFileSync(summaryPath); // TG-PATH-SAFE-011
}

module.exports = { readReport, readSummary };
