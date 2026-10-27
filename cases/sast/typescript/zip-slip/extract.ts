// TypeScript zip-slip cases (TG-TAINT-JS-ZIP-SLIP / TG-JS-ZIP-SLIP-ENTRIES-LOOP / TG-JS-TAR-PRESERVE-PATHS).
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import AdmZip from "adm-zip";
import * as tar from "tar";

export async function entriesLoop(buf: Buffer, dest: string): Promise<void> {
  const zip = await JSZip.loadAsync(buf);
  for (const [name, entry] of Object.entries(zip.files)) {
    const target: string = path.join(dest, name);
    fs.writeFileSync(target, await entry.async("nodebuffer")); // TS-ZIP-TP-001
  }
}

export function admEntries(archive: string, dest: string): void {
  const zip = new AdmZip(archive);
  for (const e of zip.getEntries()) {
    fs.writeFileSync(path.join(dest, e.entryName), e.getData()); // TS-ZIP-TP-002
  }
}

export function tarUnsafe(archive: string, dest: string) {
  return tar.x({ file: archive, cwd: dest, preservePaths: true }); // TS-ZIP-TP-003
}

export async function entriesContained(buf: Buffer, dest: string): Promise<void> {
  const zip = await JSZip.loadAsync(buf);
  for (const [name, entry] of Object.entries(zip.files)) {
    const target = path.resolve(dest, name);
    const rel = path.relative(dest, target);
    if (rel.startsWith("..") || path.isAbsolute(rel)) continue;
    fs.writeFileSync(target, await entry.async("nodebuffer")); // TS-ZIP-TN-001
  }
}

export function admContained(archive: string, dest: string): void {
  const zip = new AdmZip(archive);
  for (const e of zip.getEntries()) {
    const target = path.resolve(dest, e.entryName);
    if (!target.startsWith(dest + path.sep)) continue;
    fs.writeFileSync(target, e.getData()); // TS-ZIP-TN-002
  }
}

export function tarSafe(archive: string, dest: string) {
  return tar.x({ file: archive, cwd: dest }); // TS-ZIP-TN-003
}
