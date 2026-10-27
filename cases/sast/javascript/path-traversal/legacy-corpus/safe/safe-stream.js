// TG-PATH-SAFE-008: read stream on a trusted constant path.
const fs = require("fs");

const EXPORT_FILE = "/app/exports/daily.csv";

function streamExport(res) {
  fs.createReadStream(EXPORT_FILE).pipe(res); // TG-PATH-SAFE-008
}

module.exports = { streamExport };
