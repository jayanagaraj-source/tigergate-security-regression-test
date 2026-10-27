// TG-PATH-SAFE-007, SAFE-014: helpers and template literals built from constants.
const fs = require("fs");
const path = require("path");

const BASE_DIR = "/var/app";

function getLogPath() {
  return path.join("/var/log", "app.log");
}

function readLog() {
  return fs.readFileSync(getLogPath()); // TG-PATH-SAFE-007
}

function readManifest() {
  // Fixed template literal: only a module-level constant is interpolated.
  return fs.readFileSync(`${BASE_DIR}/manifest.json`); // TG-PATH-SAFE-014
}

module.exports = { readLog, readManifest };
