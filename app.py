"""
VulnNotas - Aplicacion web deliberadamente vulnerable para el TFG (Bloque II).
Alumno: Emilio Jose Ruiz Linares - thePower Business School.

AVISO: contiene vulnerabilidades OWASP Top 10 INTENCIONADAS con fines educativos.
NO desplegar en produccion ni en redes accesibles. Uso solo en laboratorio aislado.

Mapa de vulnerabilidades intencionadas (ver README.md):
  - A03 Injection ............ SQLi (login, busqueda, insert, /note/<id>), Command Injection (/tools/ping)
  - A03 Injection (XSS) ...... XSS reflejado (/notes?q=) y almacenado (/note/<id>)
  - A01 Broken Access Ctrl ... IDOR en /note/<id> y falta de control de rol en /admin
  - A02 Crypto Failures ...... secretos hardcodeados y contrasenas en texto plano
  - A05 Security Misconfig .... debug=True, sin cabeceras de seguridad
  - A08 Insecure Deserial. ... yaml.load inseguro en /import
  - A06 Vulnerable Comps ..... dependencias desactualizadas (requirements.txt)
"""
import os
import sqlite3
import subprocess
from flask import (Flask, request, session, redirect, url_for,
                   render_template, g, jsonify)

# --- A02: Cryptographic Failures / secretos hardcodeados (INTENCIONADO) ---
SECRET_KEY = "s3cr3t-flask-key-hardcoded-tfg-2026"          # secreto de sesion en el codigo
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"                   # credencial (falsa) hardcodeada
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_ADMIN_PASSWORD = "SuperAdmin123!"                         # password hardcodeada
# Token interno hardcodeado (INTENCIONADO): alta entropia -> lo detecta el escaner de
# secretos (Gitleaks, regla generic-api-key). Caso real de fuga de credencial (CWE-798).
INTERNAL_API_TOKEN = "Zx9Kq2Pm7Rt4Nv1Wb8Yc3Fh6Jd0Lg5Sa2Ue4Io7Q"
DB_PATH = os.environ.get("VULNNOTAS_DB", "vulnnotas.db")

app = Flask(__name__)
app.secret_key = SECRET_KEY


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);
        """
    )
    # A02: contrasenas almacenadas EN TEXTO PLANO (INTENCIONADO)
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin", "SuperAdmin123!", "admin"),
            ("emilio", "flask2026", "user"),
            ("guest", "guest", "user"),
        ],
    )
    cur.executemany(
        "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
        [
            ("admin", "Credenciales VPN", "Usuario vpn / P@ssw0rd-corporativa"),
            ("emilio", "Recordatorio", "Renovar el certificado TLS del portal"),
            ("guest", "Bienvenida", "Hola equipo, esta es mi primera nota"),
        ],
    )
    db.commit()
    db.close()


@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("notes"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # CORRECCION (fix): consulta PARAMETRIZADA -> los datos (?, ?) van separados del SQL,
        # el driver nunca los interpreta como codigo -> SQL injection imposible.
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        row = get_db().execute(query, (u, p)).fetchone()
        if row:
            session["user"] = row["username"]
            session["role"] = row["role"]
            return redirect(url_for("notes"))
        error = "Credenciales invalidas"
    return render_template("login.html", error=error)


@app.route("/notes")
def notes():
    if "user" not in session:
        return redirect(url_for("login"))
    q = request.args.get("q")
    if q is not None:
        # CORRECCION (fix): busqueda PARAMETRIZADA (el % del LIKE viaja en el dato, no en el SQL)
        sql = "SELECT * FROM notes WHERE owner = ? AND title LIKE ?"
        rows = get_db().execute(sql, (session["user"], "%" + q + "%")).fetchall()
    else:
        rows = get_db().execute(
            "SELECT * FROM notes WHERE owner = ?", (session["user"],)).fetchall()
    # q se reflejara en la plantilla con |safe -> A03 XSS reflejado (INTENCIONADO)
    return render_template("notes.html", notes=rows, q=q or "")


@app.route("/note/<int:nid>")
def note(nid):
    if "user" not in session:
        return redirect(url_for("login"))
    # A01: IDOR - sigue sin comprobar propiedad (se corrige en la fix de control de acceso)
    # CORRECCION (fix) SQLi: id parametrizado
    row = get_db().execute("SELECT * FROM notes WHERE id = ?", (nid,)).fetchone()
    if not row:
        return "Nota no encontrada", 404
    # body se renderiza con |safe -> A03 XSS almacenado (INTENCIONADO)
    return render_template("note.html", note=row)


@app.route("/note/new", methods=["GET", "POST"])
def new_note():
    if "user" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        title = request.form.get("title", "")
        body = request.form.get("body", "")
        # CORRECCION (fix): INSERT parametrizado
        get_db().execute(
            "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
            (session["user"], title, body))
        get_db().commit()
        return redirect(url_for("notes"))
    return render_template("new_note.html")


@app.route("/admin")
def admin():
    # A01: Broken Access Control - NO se comprueba el rol admin (INTENCIONADO)
    rows = get_db().execute("SELECT username, password, role FROM users").fetchall()
    return render_template("admin.html", users=rows)


@app.route("/tools/ping")
def ping():
    # A03: Command Injection - shell=True con entrada del usuario (INTENCIONADO)
    host = request.args.get("host", "127.0.0.1")
    try:
        out = subprocess.check_output("ping -c 1 " + host, shell=True,
                                      stderr=subprocess.STDOUT, timeout=8)
        text = out.decode(errors="replace")
    except Exception as e:  # noqa
        text = "error: %s" % e
    return "<pre>%s</pre><a href='/notes'>volver</a>" % text


@app.route("/import", methods=["GET", "POST"])
def import_yaml():
    if request.method == "GET":
        return ("<form method=post><textarea name=data rows=8 cols=50>"
                "titulo: demo\nnotas:\n  - a\n  - b</textarea><br>"
                "<button>Importar YAML</button></form>")
    # A08: Insecure Deserialization - yaml.load sin SafeLoader (INTENCIONADO)
    import yaml  # import perezoso: la app arranca aunque PyYAML no este instalado
    data = request.form.get("data", "")
    obj = yaml.load(data, Loader=yaml.Loader)  # loader INSEGURO (INTENCIONADO)
    return jsonify({"ok": True, "parsed": str(obj)})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # A05: Security Misconfiguration - debug=True expuesto en red (INTENCIONADO)
    app.run(host="0.0.0.0", port=5000, debug=True)
