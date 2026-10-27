// TG-PATH-SAFE-009: promise-based read of a server-generated path.
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

async function readCacheEntry() {
  const cacheFile = path.join(os.tmpdir(), `cache-${crypto.randomUUID()}.json`);
  return fs.promises.readFile(cacheFile, "utf8"); // TG-PATH-SAFE-009
}

module.exports = { readCacheEntry };
