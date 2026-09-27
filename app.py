"""
Vuln Portal - aplicacion DELIBERADAMENTE vulnerable para el Laboratorio 04 (SAST).
NO desplegar en produccion. Sirve unicamente para que Snyk/SonarCloud detecten
los fallos plantados y despues se corrijan (fase EX-05).

Cada vulnerabilidad esta marcada con un comentario  # [VULN-0x]  para localizarla.
"""

import os
import sqlite3
import hashlib
import yaml
from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__)

# [VULN-03] Secreto embebido en el codigo (CWE-798 / OWASP A07:2021)
# Clave de sesion y "API key" hardcodeadas y versionadas en git.
app.secret_key = "s3cr3t_flask_key_do_not_share_1234567890"
PAYMENTS_API_SECRET = "8f14e45fceea167a5a36dedd4bea2543d8c1a6b3f1e9d7c5a2b8e6f4d1c9a7b"

DB_PATH = "portal.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    # [VULN-04] Hashing debil: MD5 sin sal para contrasenas (CWE-327 / OWASP A02:2021)
    admin_hash = hashlib.md5("admin123".encode()).hexdigest()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("admin", admin_hash),
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # [VULN-04] La contrasena se compara con su hash MD5 (algoritmo roto)
        pw_hash = hashlib.md5(password.encode()).hexdigest()

        # [VULN-01] Inyeccion SQL: consulta construida por concatenacion de strings
        #           (CWE-89 / OWASP A03:2021). Entrada del usuario sin sanear.
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + pw_hash
            + "'"
        )
        conn = get_db()
        row = conn.execute(query).fetchone()
        conn.close()

        if row:
            session["user"] = username
            return redirect(url_for("index"))
        return render_template("login.html", error="Credenciales invalidas")

    return render_template("login.html", error=None)


@app.route("/ping")
def ping():
    # [VULN-02] Inyeccion de comandos: host del usuario pasa directo a la shell
    #           (CWE-78 / OWASP A03:2021). Ej: /ping?host=127.0.0.1;id
    host = request.args.get("host", "127.0.0.1")
    output = os.popen("ping -c 1 " + host).read()
    return "<pre>" + output + "</pre>"


@app.route("/download")
def download():
    # [VULN-05] Path traversal: el nombre de archivo no se valida
    #           (CWE-22 / OWASP A01:2021). Ej: /download?file=../../etc/passwd
    filename = request.args.get("file", "readme.txt")
    path = os.path.join("files", filename)
    with open(path, "r") as f:
        return "<pre>" + f.read() + "</pre>"


@app.route("/import", methods=["POST"])
def import_config():
    # [VULN-06] Deserializacion insegura: yaml.load sin SafeLoader ejecuta objetos
    #           arbitrarios (CWE-502 / OWASP A08:2021).
    data = request.form.get("config", "")
    config = yaml.load(data)
    return "Config cargada: " + str(config)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # debug=True tambien expone el debugger de Werkzeug (riesgo adicional)
    app.run(host="0.0.0.0", port=5000, debug=True)
