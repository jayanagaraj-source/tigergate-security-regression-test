// TypeScript format-string and log-injection cases (TG-TAINT-JS-FORMAT-STRING / TG-TAINT-JS-LOG-INJECTION).
import express, { Request, Response } from "express";
import * as util from "util";

const router = express.Router();

router.get("/ts/fmt", (req: Request, res: Response) => {
  console.log(String(req.query.fmt), req.ip); // TS-FMT-TP-001 TS-LOG-TP-001
  res.sendStatus(204);
});

router.get("/ts/format", (req: Request, res: Response) => {
  res.json({ s: util.format(String(req.body.tpl), req.ip) }); // TS-FMT-TP-002
});

router.get("/ts/safe", (req: Request, res: Response) => {
  console.log("%s from %s", JSON.stringify(req.query.q), req.ip); // TS-FMT-TN-001 TS-LOG-TN-001
  res.sendStatus(204);
});

router.get("/ts/raw", (req: Request, res: Response) => {
  console.warn("raw " + req.query.q); // TS-LOG-TP-002
  res.sendStatus(204);
});

export default router;
