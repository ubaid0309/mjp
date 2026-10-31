# ByteMart storefront - secure reference version of demo/bytemart-vulnerable/shop/app.py (DEMO DATA)
import ipaddress
import os
import secrets
import socket
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, abort, render_template, request, send_from_directory, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["BYTEMART_SECRET_KEY"]
UPLOAD_DIR = Path("/srv/bytemart/uploads")
INVOICE_DIR = Path("/srv/bytemart/invoices")
ALLOWED_AVATAR_EXT = {".png", ".jpg", ".jpeg"}
PREVIEW_HOSTS = {"images.bytemart.example"}


def db():
    return sqlite3.connect("bytemart.db")


@app.route("/login", methods=["POST"])
def login():
    cur = db().cursor()
    cur.execute("SELECT id, role, password_hash FROM users WHERE username = ?", (request.form["username"],))
    row = cur.fetchone()
    if not row or not verify_password(request.form["password"], row[2]):
        abort(401)
    session["user_id"], session["role"] = row[0], row[1]
    return {"ok": True}


@app.route("/products")
def products():
    cur = db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE category = ?", (request.args.get("category", ""),))
    return {"items": cur.fetchall()}


@app.route("/search")
def search():
    # Jinja2 templates autoescape the value
    return render_template("search.html", term=request.args.get("q", ""))


@app.route("/admin/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    ipaddress.ip_address(host)  # raises ValueError for anything that is not an IP address
    output = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5, check=False)
    return output.stdout


@app.route("/invoice")
def invoice():
    # send_from_directory rejects paths that escape INVOICE_DIR
    return send_from_directory(INVOICE_DIR, request.args.get("file", ""))


@app.route("/preview")
def preview():
    target = urlparse(request.args.get("url", ""))
    if target.scheme != "https" or target.hostname not in PREVIEW_HOSTS:
        abort(400)
    if ipaddress.ip_address(socket.gethostbyname(target.hostname)).is_private:
        abort(400)
    return requests.get(target.geturl(), timeout=5, allow_redirects=False).text


@app.route("/avatar", methods=["POST"])
def upload_avatar():
    avatar = request.files["avatar"]
    ext = Path(secure_filename(avatar.filename or "")).suffix.lower()
    if ext not in ALLOWED_AVATAR_EXT or avatar.mimetype not in {"image/png", "image/jpeg"}:
        abort(400)
    stored = f"{secrets.token_hex(16)}{ext}"
    avatar.save(UPLOAD_DIR / stored)
    return {"saved": stored}


@app.route("/admin/orders")
def admin_orders():
    if session.get("role") != "admin":  # role comes from the server-side session
        abort(403)
    return {"orders": db().cursor().execute("SELECT * FROM orders").fetchall()}


@app.route("/orders/<int:order_id>")
def order_detail(order_id):
    cur = db().cursor()
    cur.execute("SELECT * FROM orders WHERE id = ? AND customer_id = ?", (order_id, session.get("user_id")))
    order = cur.fetchone()
    if not order:
        abort(404)
    return {"order": order}


def verify_password(password, stored_hash):
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    try:
        return PasswordHasher().verify(stored_hash, password)
    except VerifyMismatchError:
        return False


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
