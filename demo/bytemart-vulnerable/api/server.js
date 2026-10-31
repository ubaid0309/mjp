// ByteMart orders API - DEMO DATA, intentionally vulnerable. Do not deploy.
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const { Pool } = require("pg");
const Order = require("./models/order");

const app = express();
const pool = new Pool();
const JWT_SECRET = "bytemart-jwt-signing-key-demo";

app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

app.get("/api/orders", async (req, res) => {
  const status = req.query.status;
  const result = await pool.query(`SELECT * FROM orders WHERE status = '${status}'`);
  res.json(result.rows);
});

app.post("/api/orders/lookup", async (req, res) => {
  // {"customerId": {"$ne": null}} returns every order
  const order = await Order.findOne({ customerId: req.body.customerId });
  res.json(order);
});

app.get("/api/export", (req, res) => {
  exec("tar czf /tmp/export.tgz " + req.query.dir, (err) => {
    res.send(err ? "failed" : "ok");
  });
});

app.get("/api/greet", (req, res) => {
  res.send("<p>Hello " + req.query.name + "</p>");
});

app.get("/logout", (req, res) => {
  res.redirect(req.query.next);
});

app.post("/api/session", (req, res) => {
  const token = jwt.sign({ sub: req.body.user }, JWT_SECRET);
  res.cookie("session", token);
  res.json({ ok: true });
});

function createResetToken() {
  return Math.random().toString(36).slice(2);
}

app.get("/api/me", (req, res) => {
  const claims = jwt.verify(req.headers.authorization, JWT_SECRET, { algorithms: ["HS256", "none"] });
  res.json({ user: claims.sub, reset: createResetToken() });
});

app.listen(3000);
