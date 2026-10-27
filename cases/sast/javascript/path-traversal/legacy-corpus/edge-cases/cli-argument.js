// TG-PATH-EDGE-002: process.argv[2] as a path.
// Classification: CONTEXT_DEPENDENT.
// Threat model A (trusted): a local CLI run by a user against their own files;
// the OS already limits them to what they may read. Not a vulnerability.
// Threat model B (untrusted): the CLI runs with more privilege than its caller
// (setuid wrapper, CI job on fork input, a service shelling out with request data).
// Then argv is attacker input and this is a path traversal.
// Exported only; nothing runs on require.
const fs = require("fs");

function printFile(argv) {
  const target = argv[2];
  return fs.readFileSync(target, "utf8"); // TG-PATH-EDGE-002
}

module.exports = { printFile, defaultArgs: () => process.argv };
