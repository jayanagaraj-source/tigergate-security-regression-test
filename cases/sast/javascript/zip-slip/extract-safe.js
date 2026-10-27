// Zip Slip negatives: every entry is resolved and rejected unless it stays inside the extraction directory.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const JSZip = require("jszip");
const unzipper = require("unzipper");
const yauzl = require("yauzl");
const AdmZip = require("adm-zip");
const tar = require("tar");

async function jszipForEachContained(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  zip.forEach((relativePath, file) => {
    const target = path.resolve(dest, relativePath);
    const rel = path.relative(dest, target);
    if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("entry escapes " + dest);
    fs.writeFileSync(target, "pending"); // JS-ZIP-TN-001
  });
}

async function jszipKeysPrefix(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  for (const name of Object.keys(zip.files)) {
    const target = path.resolve(dest, name);
    if (!target.startsWith(dest + path.sep)) continue;
    fs.writeFileSync(target, await zip.files[name].async("nodebuffer")); // JS-ZIP-TN-002
  }
}

async function jszipEntriesContained(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  for (const [name, entry] of Object.entries(zip.files)) {
    const target = path.resolve(dest, name);
    const rel = path.relative(dest, target);
    if (rel.startsWith("..") || path.isAbsolute(rel)) continue;
    fs.writeFileSync(target, await entry.async("nodebuffer")); // JS-ZIP-TN-003
  }
}

function admZipContained(archive, dest) {
  const zip = new AdmZip(archive);
  for (const e of zip.getEntries()) {
    const target = path.resolve(dest, e.entryName);
    const rel = path.relative(dest, target);
    if (rel.startsWith("..") || path.isAbsolute(rel)) continue;
    fs.writeFileSync(target, e.getData()); // JS-ZIP-TN-004
  }
}

function yauzlContained(archive, dest) {
  yauzl.open(archive, { lazyEntries: true }, (err, zipfile) => {
    zipfile.on("entry", (entry) => {
      const target = path.resolve(dest, entry.fileName);
      const rel = path.relative(dest, target);
      if (rel.startsWith("..") || path.isAbsolute(rel)) return;
      fs.mkdirSync(target, { recursive: true }); // JS-ZIP-TN-005
    });
  });
}

async function unzipperOpenContained(archive, dest) {
  const directory = await unzipper.Open.file(archive);
  for (const file of directory.files) {
    const target = path.resolve(dest, file.path);
    if (!target.startsWith(dest + path.sep)) continue;
    file.stream().pipe(fs.createWriteStream(target)); // JS-ZIP-TN-006
  }
}

function tarDefault(archive, dest) {
  return tar.x({ file: archive, cwd: dest }); // JS-ZIP-TN-007
}

function tarExplicitFalse(archive, dest) {
  return tar.x({ file: archive, cwd: dest, preservePaths: false }); // JS-ZIP-TN-008
}

function admZipBasename(archive, dest) {
  const zip = new AdmZip(archive);
  for (const e of zip.getEntries()) {
    fs.writeFileSync(path.join(dest, path.basename(e.entryName)), e.getData()); // JS-ZIP-TN-009
  }
}

function admZipGeneratedName(archive, dest) {
  const zip = new AdmZip(archive);
  for (const e of zip.getEntries()) {
    fs.writeFileSync(path.join(dest, crypto.randomUUID() + ".bin"), e.getData()); // JS-ZIP-TN-010
  }
}

function admZipLibraryExtract(archive, dest) {
  new AdmZip(archive).extractAllTo(dest, true); // JS-ZIP-TN-011
}

module.exports = { jszipForEachContained, jszipKeysPrefix, jszipEntriesContained, admZipContained, yauzlContained,
  unzipperOpenContained, tarDefault, tarExplicitFalse, admZipBasename, admZipGeneratedName, admZipLibraryExtract };
