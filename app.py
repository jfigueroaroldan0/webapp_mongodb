"""
================================================================================
  DocVault (VULNERABLE) - Explorador de MongoDB con inyeccion NoSQL
================================================================================

  Esta es la version VULNERABLE de la aplicacion. El buscador de documentos
  construye la consulta concatenando el texto del usuario dentro de una clausula
  $where (JavaScript que Mongo evalua), por lo que es vulnerable a inyeccion
  NoSQL. La version corregida esta en el proyecto hermano 'docvault_seguro'.

  - Login contra las CUENTAS REALES del servidor MongoDB.
  - Muestra las bases de datos y colecciones accesibles para ese usuario,
    segun los permisos que Mongo le concede.
  - Permite acceder a los documentos y hacer CRUD (insertar, editar, borrar).

  Ejecutar:
    python app.py
  Payload de demostracion en el buscador:
    x') >= 0 || true || ('
================================================================================
"""

import os
import json
import secrets
from functools import wraps
from urllib.parse import quote_plus

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from pymongo import MongoClient
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError, PyMongoError
from bson.objectid import ObjectId
from bson.errors import InvalidId
from bson import json_util

# ------------------------------------------------------------------ CONFIG ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave-demo-no-usar-en-produccion")

MONGO_HOST  = os.environ.get("MONGO_HOST", "192.168.122.36")
MONGO_PORT  = os.environ.get("MONGO_PORT", "27017")
AUTH_SOURCE = os.environ.get("AUTH_SOURCE", "admin")

VULNERABLE = True          # <-- esta aplicacion es la vulnerable
HIDDEN_DBS = {"local", "config"}
LIMIT = 300

ADMIN_ROLES = {
    "root", "dbOwner", "readWrite", "readWriteAnyDatabase",
    "dbAdmin", "dbAdminAnyDatabase", "userAdmin", "userAdminAnyDatabase",
    "clusterAdmin",
}

ACTIVE_CLIENTS = {}  # token de sesion -> MongoClient autenticado


# ----------------------------------------------------------------- HELPERS ---
def build_uri(username, password):
    u, p = quote_plus(username), quote_plus(password)
    return f"mongodb://{u}:{p}@{MONGO_HOST}:{MONGO_PORT}/?authSource={AUTH_SOURCE}"


def authenticate(username, password):
    cli = MongoClient(build_uri(username, password), serverSelectionTimeoutMS=4000)
    cli.admin.command("ping")
    status = cli.admin.command("connectionStatus")
    roles = status["authInfo"]["authenticatedUserRoles"]
    return cli, roles


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = session.get("token")
        if not token or token not in ACTIVE_CLIENTS:
            session.clear()
            flash("Tu sesion ha caducado. Inicia sesion de nuevo.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def client():
    return ACTIVE_CLIENTS[session["token"]]


def current_user():
    return {
        "username": session.get("username"),
        "roles": session.get("roles", []),
        "is_admin": session.get("is_admin", False),
    }


def list_databases():
    try:
        names = client().list_database_names()
    except OperationFailure:
        names = sorted({r["db"] for r in session.get("role_pairs", []) if r.get("db")})
    return [n for n in names if n not in HIDDEN_DBS]


def resolve_id(id_str):
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError):
        return id_str


def doc_to_view(doc):
    body = {k: v for k, v in doc.items() if k != "_id"}
    return {"id": str(doc.get("_id")), "json": json_util.dumps(body, indent=2, ensure_ascii=False)}


# ============================================================ LOGIN / LOGOUT =
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            cli, roles = authenticate(username, password)
        except OperationFailure:
            flash("Credenciales de Mongo incorrectas.", "danger")
            return render_template("login.html", vulnerable=VULNERABLE)
        except (ServerSelectionTimeoutError, PyMongoError):
            flash("No se pudo contactar con el servidor MongoDB.", "danger")
            return render_template("login.html", vulnerable=VULNERABLE)

        token = secrets.token_hex(16)
        ACTIVE_CLIENTS[token] = cli
        session["token"] = token
        session["username"] = username
        session["role_pairs"] = roles
        session["roles"] = sorted({r["role"] for r in roles})
        session["is_admin"] = any(r["role"] in ADMIN_ROLES for r in roles)
        flash(f"Conectado a Mongo como {username}.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", vulnerable=VULNERABLE)


@app.route("/logout")
def logout():
    cli = ACTIVE_CLIENTS.pop(session.get("token"), None)
    if cli:
        cli.close()
    session.clear()
    flash("Sesion cerrada.", "info")
    return redirect(url_for("login"))


# ================================================================= DASHBOARD =
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    dbname = request.args.get("db", "")
    colname = request.args.get("col", "")
    q = request.args.get("q", "")

    databases = collections = docs = None
    error = None
    try:
        if not dbname:
            databases = list_databases()
        elif not colname:
            collections = sorted(client()[dbname].list_collection_names())
        else:
            docs = read_documents(dbname, colname, q)
    except OperationFailure as e:
        error = f"Mongo denego el acceso: {e.details.get('errmsg', e)}"
    except PyMongoError as e:
        error = f"Error de Mongo: {e}"

    return render_template(
        "dashboard.html",
        user=user, vulnerable=VULNERABLE,
        dbname=dbname, colname=colname, q=q,
        databases=databases, collections=collections, docs=docs, error=error,
    )


# --------------------------------------------------- BUSCADOR VULNERABLE -----
def read_documents(dbname, colname, q):
    """
    !!! VULNERABLE !!!
    Construye un $where (JavaScript) concatenando la entrada del usuario. Un
    atacante puede romper la cadena y controlar la logica de la consulta.
        Payload de ejemplo:  x') >= 0 || true || ('
        -> JSON.stringify(this).indexOf('x') >= 0 || true || ('') >= 0
        que es siempre verdadero: devuelve TODOS los documentos.
    """
    col = client()[dbname][colname]
    if q:
        where = "JSON.stringify(this).indexOf('%s') >= 0" % q
        docs = list(col.find({"$where": where}).limit(LIMIT))
    else:
        docs = list(col.find({}).limit(LIMIT))
    return [doc_to_view(d) for d in docs]


# ====================================================== CRUD DE DOCUMENTOS ===
@app.route("/documents/create", methods=["POST"])
@login_required
def create_document():
    dbname = request.form.get("db", "")
    colname = request.form.get("col", "")
    raw = request.form.get("json", "").strip()
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("El documento debe ser un objeto JSON.")
        client()[dbname][colname].insert_one(data)
        flash("Documento insertado.", "success")
    except (ValueError, json.JSONDecodeError) as e:
        flash(f"JSON invalido: {e}", "danger")
    except OperationFailure:
        flash("Mongo denego la operacion: tu cuenta no tiene permiso de escritura.", "danger")
    return redirect(url_for("dashboard", db=dbname, col=colname))


@app.route("/documents/update", methods=["POST"])
@login_required
def update_document():
    dbname = request.form.get("db", "")
    colname = request.form.get("col", "")
    doc_id = request.form.get("id", "")
    raw = request.form.get("json", "").strip()
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("El documento debe ser un objeto JSON.")
        data.pop("_id", None)
        client()[dbname][colname].update_one({"_id": resolve_id(doc_id)}, {"$set": data})
        flash("Documento actualizado.", "success")
    except (ValueError, json.JSONDecodeError) as e:
        flash(f"JSON invalido: {e}", "danger")
    except OperationFailure:
        flash("Mongo denego la operacion: tu cuenta no tiene permiso de escritura.", "danger")
    return redirect(url_for("dashboard", db=dbname, col=colname))


@app.route("/documents/delete", methods=["POST"])
@login_required
def delete_document():
    dbname = request.form.get("db", "")
    colname = request.form.get("col", "")
    doc_id = request.form.get("id", "")
    try:
        client()[dbname][colname].delete_one({"_id": resolve_id(doc_id)})
        flash("Documento borrado.", "info")
    except OperationFailure:
        flash("Mongo denego la operacion: tu cuenta no tiene permiso de escritura.", "danger")
    return redirect(url_for("dashboard", db=dbname, col=colname))


# =============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  DocVault - VERSION VULNERABLE (inyeccion NoSQL en el buscador)")
    print(f"  Mongo: {MONGO_HOST}:{MONGO_PORT}  (authSource={AUTH_SOURCE})")
    print("  Payload de demo en el buscador:  x') >= 0 || true || ('")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
