# ByteMart storefront - DEMO DATA, intentionally vulnerable. Do not deploy.
import os
import sqlite3
import subprocess

import requests
from flask import Flask, abort, render_template_string, request, send_file, session

from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
UPLOAD_DIR = "/srv/bytemart/uploads"
INVOICE_DIR = "/srv/bytemart/invoices"


def db():
    return sqlite3.connect("bytemart.db")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    cur = db().cursor()
    # Vulnerable: user input concatenated into SQL
    cur.execute(f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'")
    row = cur.fetchone()
    if not row:
        abort(401)
    session["user_id"], session["role"] = row
    return {"ok": True}


@app.route("/products")
def products():
    category = request.args.get("category", "")
    query = "SELECT id, name, price FROM products WHERE category = '" + category + "'"
    cur = db().cursor()
    cur.execute(query)
    return {"items": cur.fetchall()}


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # Vulnerable: reflected into HTML without escaping
    return render_template_string("<h2>Results for " + term + "</h2>")


@app.route("/admin/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/invoice")
def invoice():
    name = request.args.get("file")
    # Vulnerable: ../../etc/passwd escapes INVOICE_DIR
    return send_file(os.path.join(INVOICE_DIR, name))


@app.route("/preview")
def preview():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text


@app.route("/avatar", methods=["POST"])
def upload_avatar():
    avatar = request.files["avatar"]
    avatar.save(os.path.join(UPLOAD_DIR, avatar.filename))
    return {"saved": avatar.filename}


@app.route("/admin/orders")
def admin_orders():
    # Vulnerable: the client decides whether it is an admin
    if request.args.get("role") == "admin":
        return {"orders": db().cursor().execute("SELECT * FROM orders").fetchall()}
    abort(403)


@app.route("/orders/<int:order_id>")
def order_detail(order_id):
    # Weak access control (IDOR): any logged-in user can read any order.
    # Pattern rules cannot prove this; it is listed in the README for manual review.
    cur = db().cursor()
    cur.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return {"order": cur.fetchone()}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
