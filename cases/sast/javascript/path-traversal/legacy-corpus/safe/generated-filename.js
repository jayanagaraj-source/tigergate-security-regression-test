// TG-PATH-SAFE-003: server-generated UUID filename; user input never touches the path.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function saveUpload(content) {
  const filename = `${crypto.randomUUID()}.txt`;

  fs.writeFileSync( // TG-PATH-SAFE-003
    path.join("/app/uploads", filename),
    content
  );
  return filename;
}

module.exports = { saveUpload };
