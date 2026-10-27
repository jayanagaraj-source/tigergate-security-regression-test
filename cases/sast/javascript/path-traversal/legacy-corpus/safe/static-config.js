// TG-PATH-SAFE-002, SAFE-012: trusted static configuration objects.
const fs = require("fs");

const config = {
  logFile: "/var/log/app.log"
};

const PATHS = Object.freeze({
  audit: "/var/log/audit.log",
  access: "/var/log/access.log"
});

function readLog() {
  return fs.readFileSync(config.logFile); // TG-PATH-SAFE-002
}

function readAudit() {
  return fs.readFileSync(PATHS.audit); // TG-PATH-SAFE-012
}

module.exports = { readLog, readAudit };
