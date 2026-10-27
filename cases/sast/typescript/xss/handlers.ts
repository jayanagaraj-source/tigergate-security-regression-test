// TypeScript Express handlers for TG-TAINT-JS-XSS (positives and negatives side by side).
import express, { Request, Response } from "express";
import * as fs from "fs";
import escapeHtml from "escape-html";

const router = express.Router();
const ASSETS: Record<string, string> = { logo: "/srv/assets/logo.png" };

router.get("/ts/hello", (req: Request, res: Response) => {
  res.send(`<p>Hi ${req.query.who}</p>`); // TS-XSS-TP-001
});

router.get("/ts/html", (req: Request, res: Response) => {
  res.type("html").send(String(req.query.fragment)); // TS-XSS-TP-002
});

router.get("/ts/status", (req: Request, res: Response) => {
  res.status(400).send("<em>Bad field " + req.params.field + "</em>"); // TS-XSS-TP-003
});

router.get("/ts/asset", (req: Request, res: Response) => {
  res.send(fs.readFileSync(ASSETS[String(req.query.name)])); // TS-XSS-TN-001
});

router.get("/ts/escaped", (req: Request, res: Response) => {
  res.send("<p>" + escapeHtml(String(req.query.who)) + "</p>"); // TS-XSS-TN-002
});

router.get("/ts/static", (_req: Request, res: Response) => {
  res.send("<p>Static</p>"); // TS-XSS-TN-003
});

export default router;
