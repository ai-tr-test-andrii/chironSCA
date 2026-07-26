import os
import pickle
import sqlite3
import logging
import subprocess
import urllib.request
from flask import Flask, request, redirect, Response, make_response, send_file

app = Flask(__name__)
db_connection = None


# =============================================================================
# CRITICAL: SQL Injection (CWE-89)
# =============================================================================

@app.route("/api/user/get")
def sqli_user_get():
    param = request.args.get("id", "")
    query = f"SELECT id, username, email FROM users WHERE id = {param}"
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")

@app.route("/api/user/search")
def sqli_user_search():
    term = request.args.get("q", "")
    query = "SELECT id, username, email FROM users WHERE username LIKE '%" + term + "%'"
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")

@app.route("/api/product/get")
def sqli_product_get():
    param = request.args.get("id", "")
    query = f"SELECT id, name, price FROM products WHERE id = {param}"
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")

@app.route("/api/order/get")
def sqli_order_get():
    param = request.args.get("id", "")
    query = "SELECT id, user_id, total FROM orders WHERE id = %s" % param
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")

@app.route("/api/customer/get")
def sqli_customer_get():
    param = request.args.get("id", "")
    query = f"SELECT id, first_name, email FROM customers WHERE id = {param}"
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")

@app.route("/api/employee/get")
def sqli_employee_get():
    param = request.args.get("id", "")
    query = "SELECT id, name, department FROM employees WHERE id = " + param
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")


# =============================================================================
# CRITICAL: Command Injection (CWE-78)
# =============================================================================

@app.route("/cmd/ping")
def cmd_ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)
    return Response("Executed", mimetype="text/plain")

@app.route("/cmd/dns")
def cmd_dns():
    domain = request.args.get("domain", "")
    # Pass command as an argv list with shell=False to prevent command injection (CWE-77).
    # The domain value is passed as a separate argument, so the shell never interprets it.
    result = subprocess.check_output(["nslookup", domain], shell=False)
    return Response(result, mimetype="text/plain")


# =============================================================================
# HIGH: Reflected XSS (CWE-79)
# =============================================================================

@app.route("/page/greet")
def xss_greet():
    name = request.args.get("name", "")
    html = f"<html><body><h1>Hello, {name}!</h1></body></html>"
    return Response(html, mimetype="text/html")

@app.route("/page/error")
def xss_error():
    msg = request.args.get("msg", "")
    html = "<html><body><div class='error'>Error: " + msg + "</div></body></html>"
    return Response(html, mimetype="text/html")


# =============================================================================
# HIGH: Path Traversal (CWE-22)
# =============================================================================

@app.route("/files/document")
def path_document():
    fname = request.args.get("name", "")
    with open("/var/data/" + fname, "r") as f:
        content = f.read()
    return Response(content, mimetype="text/plain")

@app.route("/files/config")
def path_config():
    fname = request.args.get("name", "")
    with open("/etc/app/" + fname, "r") as f:
        content = f.read()
    return Response(content, mimetype="text/plain")


# =============================================================================
# HIGH: SSRF (CWE-918)
# =============================================================================

@app.route("/net/fetch")
def ssrf_fetch():
    url = request.args.get("url", "")
    resp = urllib.request.urlopen(url)
    return Response(resp.read(), mimetype="text/plain")


# =============================================================================
# HIGH: Deserialization (CWE-502)
# =============================================================================

@app.route("/data/import", methods=["POST"])
def deser_import():
    raw = request.get_data()
    data = pickle.loads(raw)
    return Response(f"Loaded {len(data)} items", mimetype="text/plain")


# =============================================================================
# Initialization
# =============================================================================

def init_db():
    global db_connection
    db_connection = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = db_connection.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, role TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin@test.com', 'admin123', 'admin')")
    cursor.execute("INSERT INTO users VALUES (2, 'user1', 'user1@test.com', 'pass123', 'user')")
    db_connection.commit()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=True)
