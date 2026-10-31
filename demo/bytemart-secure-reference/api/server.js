// ByteMart orders API - secure reference version (DEMO DATA)
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { execFile } = require("child_process");
const { Pool } = require("pg");
const Order = require("./models/order");

const app = express();
const pool = new Pool();
const signingKey = process.env.BYTEMART_JWT_KEY;
const EXPORT_DIRS = new Set(["daily", "weekly"]);

app.use(express.json({ limit: "100kb" }));
app.use(cors({ origin: ["https://shop.bytemart.example"], credentials: true }));

app.get("/api/orders", async (req, res) => {
  const result = await pool.query("SELECT * FROM orders WHERE status = $1", [String(req.query.status)]);
  res.json(result.rows);
});

app.post("/api/orders/lookup", async (req, res) => {
  const order = await Order.findOne({ customerId: String(req.body.customerId) });
  res.json(order);
});

app.get("/api/export", (req, res) => {
  if (!EXPORT_DIRS.has(req.query.dir)) return res.status(400).json({ error: "unknown export" });
  execFile("tar", ["czf", "/tmp/export.tgz", `/data/exports/${req.query.dir}`], (err) => {
    res.json({ ok: !err });
  });
});

app.get("/api/greet", (req, res) => {
  res.json({ greeting: `Hello ${String(req.query.name ?? "")}` });
});

app.get("/logout", (req, res) => {
  const next = String(req.query.next ?? "/");
  res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
});

app.post("/api/session", (req, res) => {
  const token = jwt.sign({ sub: req.body.user }, signingKey, { algorithm: "HS256", expiresIn: "1h" });
  res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
  res.json({ ok: true });
});

function createResetToken() {
  return crypto.randomBytes(32).toString("base64url");
}

app.get("/api/me", (req, res) => {
  const claims = jwt.verify(req.headers.authorization, signingKey, { algorithms: ["HS256"] });
  res.json({ user: claims.sub, reset: createResetToken() });
});

app.listen(3000);
