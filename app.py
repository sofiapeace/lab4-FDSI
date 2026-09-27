"""
Vuln Portal - version REMEDIADA (Laboratorio 04, EX-05).

Cada correccion esta marcada con  # [FIX-0x]  y se corresponde con el
# [VULN-0x] del baseline vulnerable (tag v0-vulnerable).

Cambios de configuracion: los secretos ahora se leen de variables de entorno
(ver .env.example) y el modo debug queda desactivado.
"""

import os
import re
import sqlite3
import subprocess

import bcrypt
import yaml
from flask import Flask, request, render_template, redirect, url_for, session
from markupsafe import escape

app = Flask(__name__)

# [FIX-03] Secretos fuera del codigo: se leen del entorno (CWE-798 corregido).
#          Si falta la variable, la app no arranca en vez de usar un valor debil.
app.secret_key = os.environ["FLASK_SECRET_KEY"]
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")

DB_PATH = "portal.db"

# Directorio base permitido para descargas (para el FIX-05).
FILES_DIR = os.path.abspath("files")

# Nombre de host valido: IPv4/hostname simple, sin metacaracteres de shell.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


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
    # [FIX-04] Hashing fuerte con bcrypt (con sal automatica) en vez de MD5
    #          (CWE-327 corregido).
    admin_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
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

        # [FIX-01] Consulta parametrizada: la entrada del usuario ya no se
        #          concatena a la SQL (CWE-89 corregido).
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # [FIX-04] Verificacion del hash bcrypt en tiempo constante.
        if row and bcrypt.checkpw(password.encode(), row["password"].encode()):
            session["user"] = username
            return redirect(url_for("index"))
        return render_template("login.html", error="Credenciales invalidas")

    return render_template("login.html", error=None)


@app.route("/ping")
def ping():
    # [FIX-02] Inyeccion de comandos corregida (CWE-78):
    #          1) se valida el host contra una lista blanca de caracteres,
    #          2) se usa subprocess con lista de argumentos (sin shell).
    host = request.args.get("host", "127.0.0.1")
    if not HOSTNAME_RE.match(host):
        return "Host invalido", 400
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    # [FIX-08] Salida escapada antes de meterla en HTML (CWE-79 corregido,
    #          hallazgo que Snyk encontro de bono en el primer escaneo).
    return "<pre>" + str(escape(result.stdout)) + "</pre>"


@app.route("/download")
def download():
    # [FIX-05] Path traversal corregido (CWE-22): se normaliza la ruta y se
    #          verifica que siga dentro de FILES_DIR antes de abrir el archivo.
    filename = request.args.get("file", "readme.txt")
    requested = os.path.abspath(os.path.join(FILES_DIR, filename))
    if not requested.startswith(FILES_DIR + os.sep):
        return "Ruta no permitida", 403
    if not os.path.isfile(requested):
        return "Archivo no encontrado", 404
    with open(requested, "r") as f:
        # [FIX-08] Salida escapada antes de meterla en HTML (CWE-79 corregido).
        return "<pre>" + str(escape(f.read())) + "</pre>"


@app.route("/import", methods=["POST"])
def import_config():
    # [FIX-06] Deserializacion segura: yaml.safe_load no instancia objetos
    #          arbitrarios (CWE-502 corregido).
    data = request.form.get("config", "")
    try:
        config = yaml.safe_load(data)
    except yaml.YAMLError:
        return "YAML invalido", 400
    # [FIX-08] Salida escapada antes de meterla en HTML (CWE-79 corregido).
    return "Config cargada: " + str(escape(str(config)))


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # [FIX] debug desactivado: no se expone el debugger de Werkzeug.
    app.run(host="127.0.0.1", port=5000, debug=False)
