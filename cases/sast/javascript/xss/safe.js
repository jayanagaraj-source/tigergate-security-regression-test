// Negatives for TG-TAINT-JS-XSS: binary bodies, escaped or sanitized values, static HTML, non-HTML types.
const express = require("express");
const fs = require("fs");
const escapeHtml = require("escape-html");
const he = require("he");
const DOMPurify = require("isomorphic-dompurify");

const router = express.Router();
const DOCUMENTS = { terms: "/srv/docs/terms.pdf", privacy: "/srv/docs/privacy.pdf" };

router.get("/download", (req, res) => {
  res.send(fs.readFileSync(DOCUMENTS[req.query.doc])); // JS-XSS-TN-001
});

router.get("/download-status", (req, res) => {
  res.status(200).send(fs.readFileSync(DOCUMENTS[req.query.doc])); // JS-XSS-TN-002
});

router.get("/download-async", async (req, res) => {
  res.send(await fs.promises.readFile(DOCUMENTS[req.query.doc])); // JS-XSS-TN-003
});

router.get("/greet", (req, res) => {
  res.send("<h1>Hello " + escapeHtml(req.query.name) + "</h1>"); // JS-XSS-TN-004
});

router.get("/search", (req, res) => {
  res.send("<p>Results for " + he.encode(req.query.q) + "</p>"); // JS-XSS-TN-005
});

router.get("/about", (req, res) => {
  res.send("<p>About this shop</p>"); // JS-XSS-TN-006
});

router.get("/profile", (req, res) => {
  res.json({ name: req.query.name }); // JS-XSS-TN-007
});

router.get("/echo", (req, res) => {
  res.send({ user: req.query.user }); // JS-XSS-TN-008
});

router.get("/plain", (req, res) => {
  res.type("text/plain").send(req.query.msg); // JS-XSS-TN-009
});

router.get("/plain-header", (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send(req.query.msg); // JS-XSS-TN-010
});

router.post("/rich", (req, res) => {
  res.send(DOMPurify.sanitize(req.body.html)); // JS-XSS-TN-011
});

router.get("/count", (req, res) => {
  res.send("<b>" + Number(req.query.n) + "</b>"); // JS-XSS-TN-012
});

router.get("/json-type", (req, res) => {
  res.type("application/json").send(JSON.stringify({ q: req.query.q })); // JS-XSS-TN-013
});

module.exports = router;
