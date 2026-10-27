// TG-PATH-TP-012: typed Express request, query value reaches fs.readFileSync.
import express, { Request, Response } from "express";
import * as fs from "fs";
import * as path from "path";

interface FileQuery {
  file?: string;
}

export const router = express.Router();

router.get("/ts-file", (req: Request<{}, unknown, unknown, FileQuery>, res: Response) => {
  const requested = req.query.file ?? "";
  const target = path.join("/app/files", requested);
  res.send(fs.readFileSync(target)); // TG-PATH-TP-012
});
