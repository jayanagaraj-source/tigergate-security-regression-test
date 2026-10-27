// Zip Slip positives: archive entry names reach the path of a file write without containment.
const fs = require("fs");
const path = require("path");
const JSZip = require("jszip");
const unzipper = require("unzipper");
const yauzl = require("yauzl");
const AdmZip = require("adm-zip");
const tar = require("tar");

async function jszipForEach(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  zip.forEach((relativePath, file) => {
    fs.writeFileSync(path.join(dest, relativePath), "pending"); // JS-ZIP-TP-001
  });
}

async function jszipKeys(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  for (const name of Object.keys(zip.files)) {
    const data = await zip.files[name].async("nodebuffer");
    fs.writeFileSync(path.join(dest, name), data); // JS-ZIP-TP-002
  }
}

async function jszipEntries(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  for (const [name, entry] of Object.entries(zip.files)) {
    fs.writeFileSync(path.join(dest, name), await entry.async("nodebuffer")); // JS-ZIP-TP-003
  }
}

async function jszipEntriesVariable(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  for (const [name, entry] of Object.entries(zip.files)) {
    const target = path.join(dest, name);
    fs.writeFileSync(target, await entry.async("nodebuffer")); // JS-ZIP-TP-004
  }
}

async function unzipperOpen(archive, dest) {
  const directory = await unzipper.Open.file(archive);
  for (const file of directory.files) {
    file.stream().pipe(fs.createWriteStream(path.join(dest, file.path))); // JS-ZIP-TP-005
  }
}

function unzipperParse(archive, dest) {
  fs.createReadStream(archive)
    .pipe(unzipper.Parse())
    .on("entry", (entry) => {
      entry.pipe(fs.createWriteStream(path.join(dest, entry.path))); // JS-ZIP-TP-006
    });
}

function yauzlEntries(archive, dest) {
  yauzl.open(archive, { lazyEntries: true }, (err, zipfile) => {
    zipfile.on("entry", (entry) => {
      fs.mkdirSync(path.join(dest, entry.fileName), { recursive: true }); // JS-ZIP-TP-007
      zipfile.readEntry();
    });
  });
}

function admZipEntries(archive, dest) {
  const zip = new AdmZip(archive);
  zip.getEntries().forEach((e) => {
    fs.writeFileSync(path.join(dest, e.entryName), e.getData()); // JS-ZIP-TP-008
  });
}

function tarPreserve(archive, dest) {
  return tar.x({ file: archive, cwd: dest, preservePaths: true }); // JS-ZIP-TP-009
}

function tarExtractPreserve(dest) {
  return tar.extract({ cwd: dest, preservePaths: true }); // JS-ZIP-TP-010
}

function admZipAbsolute(archive, dest) {
  const zip = new AdmZip(archive);
  for (const e of zip.getEntries()) {
    fs.writeFileSync(path.resolve(dest, e.entryName), e.getData()); // JS-ZIP-TP-011
  }
}

function admZipPrefixOnly(archive, dest) {
  const zip = new AdmZip(archive);
  for (const e of zip.getEntries()) {
    const target = path.resolve(dest, e.entryName);
    if (!target.startsWith(dest)) continue;
    fs.writeFileSync(target, e.getData()); // JS-ZIP-TP-012
  }
}

async function jszipValues(buf, dest) {
  const zip = await JSZip.loadAsync(buf);
  for (const entry of Object.values(zip.files)) {
    fs.writeFileSync(path.join(dest, entry.name), "pending"); // JS-ZIP-TP-013
  }
}

module.exports = { jszipForEach, jszipKeys, jszipEntries, jszipEntriesVariable, unzipperOpen, unzipperParse,
  yauzlEntries, admZipEntries, tarPreserve, tarExtractPreserve, admZipAbsolute, admZipPrefixOnly, jszipValues };
