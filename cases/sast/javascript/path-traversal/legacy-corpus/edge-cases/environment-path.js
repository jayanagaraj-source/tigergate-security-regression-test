// TG-PATH-EDGE-003: process.env.FILE_PATH as a path.
// Classification: CONTEXT_DEPENDENT.
// Trusted when set by the operator (deployment config, container spec).
// Untrusted when the environment is populated from request data (CGI-style
// HTTP_* variables, per-tenant job runners that copy user settings into env).
const fs = require("fs");

function loadConfiguredFile() {
  const configured = process.env.FILE_PATH || "/etc/app/default.conf";
  return fs.readFileSync(configured, "utf8"); // TG-PATH-EDGE-003
}

module.exports = { loadConfiguredFile };
