"""
app.py — NETMORPH SaaS (Flask)
===============================
Point d'entrée Flask. Remplace le main.py PyQt6 de App_V2.

Routes :
  GET  /                        — dashboard (upload ou vue courante)
  POST /upload                  — importe un fichier XML (WG ou pfSense)
  GET  /export                  — télécharge le XML actif
  POST /api/add_rule            — injecte une règle firewall
  POST /api/add_interface       — injecte une interface / VLAN
  POST /api/delete_rule         — supprime une règle
  POST /api/migrate             — lance la migration (WG ↔ pfSense)
  POST /api/reset_migration     — annule l'étape 1 du wizard
  GET  /api/pick_source         — détecte le type du XML courant (étape 1)
  GET  /api/audit               — retourne les findings d'audit en JSON
"""

import os
import time
import shutil
import traceback
import xml.etree.ElementTree as ET
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    send_file, jsonify, Response,
)
from werkzeug.utils import secure_filename

from utils import (
    app_dir, template_dir, session_dir, get_working_xml,
    get_base_xml, get_modified_xml, set_session_context,
)
from parser import get_dashboard_data
from engine import save_rule_xml, save_interface_xml, perform_migration, delete_rule_xml
from audit import run_audit
from ui_template import get_ui, get_css, get_js

# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "netmorph-dev-secret-change-in-prod")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max upload

# ── Nettoyage auto des sessions expirées (> 24h) ─────────────────────────────
_UPLOAD_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "uploads"
)
_SESSION_MAX_AGE = 24 * 3600  # 24 heures


def _cleanup_old_sessions():
    """Supprime les dossiers de session de plus de 24h."""
    if not os.path.isdir(_UPLOAD_ROOT):
        return
    now = time.time()
    for name in os.listdir(_UPLOAD_ROOT):
        path = os.path.join(_UPLOAD_ROOT, name)
        if os.path.isdir(path):
            age = now - os.path.getmtime(path)
            if age > _SESSION_MAX_AGE:
                shutil.rmtree(path, ignore_errors=True)


# Nettoyage au démarrage
_cleanup_old_sessions()


# ── Authentification ──────────────────────────────────────────────────────────

USERS = {"iutuser": "iutval"}


def login_required(f):
    """Décorateur : redirige vers /login si pas authentifié."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")
        if USERS.get(user) == pwd:
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Identifiants incorrects"
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>NETMORPH — Connexion</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0a0a1a; color:#e0e0e0; font-family:'Segoe UI',sans-serif;
         display:flex; justify-content:center; align-items:center; min-height:100vh;
         background-image: radial-gradient(circle at 20% 50%, rgba(255,45,85,0.05) 0%, transparent 50%),
                           radial-gradient(circle at 80% 50%, rgba(139,92,246,0.05) 0%, transparent 50%); }}
  .login-box {{ background:#12122a; border:1px solid #1e1e3a; border-radius:20px;
               padding:48px; width:400px; text-align:center;
               box-shadow: 0 20px 60px rgba(0,0,0,0.5); }}
  .login-logo {{ width:120px; height:120px; margin:0 auto 16px; border-radius:16px;
                border:2px solid rgba(0,229,255,0.3); overflow:hidden; }}
  .login-logo img {{ width:100%; height:100%; object-fit:cover; }}
  .login-box h1 {{ color:#ff2d55; font-size:32px; margin-bottom:4px;
                  background:linear-gradient(135deg,#ff2d55,#8b5cf6);
                  -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
  .login-box .subtitle {{ color:#00e5ff; font-size:13px; letter-spacing:2px;
                          text-transform:uppercase; margin-bottom:24px; }}
  .login-box p.desc {{ color:#888; margin-bottom:24px; font-size:14px; }}
  .login-box input {{ width:100%; padding:14px 16px; margin-bottom:16px; border:1px solid #2a2a4a;
                     border-radius:10px; background:#1a1a2e; color:#e0e0e0; font-size:15px;
                     transition:border-color 0.2s; }}
  .login-box input:focus {{ outline:none; border-color:#ff2d55; box-shadow:0 0 12px rgba(255,45,85,0.2); }}
  .login-box button {{ width:100%; padding:14px; border:none; border-radius:10px;
                      background:linear-gradient(135deg,#ff2d55,#8b5cf6); color:#fff;
                      font-size:16px; font-weight:bold; cursor:pointer;
                      transition:opacity 0.2s, transform 0.1s; }}
  .login-box button:hover {{ opacity:0.9; transform:translateY(-1px); }}
  .login-box button:active {{ transform:translateY(0); }}
  .error {{ color:#ff4444; margin-bottom:16px; font-size:14px;
           background:rgba(255,68,68,0.1); padding:8px 12px; border-radius:8px; }}
  .footer {{ margin-top:24px; color:#555; font-size:12px; }}
</style></head><body>
<div class="login-box">
  <div class="login-logo"><img src="/logo.png" alt="NETMORPH"></div>
  <h1>NETMORPH</h1>
  <div class="subtitle">Firewall Migration Platform</div>
  <p class="desc">Connectez-vous pour accéder à la plateforme</p>
  {"<div class='error'>" + error + "</div>" if error else ""}
  <form method="post">
    <input type="text" name="username" placeholder="👤  Identifiant" autofocus required>
    <input type="password" name="password" placeholder="🔒  Mot de passe" required>
    <button type="submit">Se connecter</button>
  </form>
  <div class="footer">Projet Tutoré IUT Valence — 2025/2026</div>
</div></body></html>"""


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Session helpers ───────────────────────────────────────────────────────────

def ensure_session() -> str:
    """Crée un ID de session si absent."""
    if "sid" not in session:
        import uuid
        session["sid"] = uuid.uuid4().hex
    return session["sid"]


def sid() -> str:
    return ensure_session()


_last_cleanup = time.time()


@app.before_request
def setup_session_context():
    """
    Initialise le contexte de session thread-local avant chaque requête.
    Permet à engine.py (via app_dir()) d'écrire dans le bon dossier utilisateur.
    """
    # Pas de contexte session sur la page de login ou le logo
    if request.endpoint in ("login", "logo", "logout", "static"):
        return
    if not session.get("logged_in"):
        return
    global _last_cleanup
    set_session_context(sid())
    # Nettoyage des vieilles sessions toutes les heures
    if time.time() - _last_cleanup > 3600:
        _last_cleanup = time.time()
        _cleanup_old_sessions()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    """Dashboard principal — génère le même HTML que App_V2."""
    s = sid()
    xml_path = get_working_xml()
    data = get_dashboard_data(xml_path) if xml_path else None

    try:
        audit_results = run_audit(xml_path) if xml_path else None
    except Exception:
        audit_results = None

    mig_state = {
        "src_path": session.get("mig_src"),
        "src_type": session.get("mig_src_type"),
        "src_name": session.get("mig_src_name"),
    }

    html_body = get_ui(data, mig_state, audit_results=audit_results)
    css = get_css()
    js  = get_js()

    full_html = (
        '<!DOCTYPE html>'
        '<html lang="fr">'
        '<head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        + css +
        '</head><body>'
        + html_body
        + js +
        '</body></html>'
    )
    return Response(full_html, mimetype='text/html; charset=utf-8')


@app.route("/logo.png")
def logo():
    """Sert le logo NETMORPH."""
    logo_path = os.path.join(os.path.dirname(__file__), "logo.png")
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype="image/png")
    return "", 404


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    """Importe un fichier XML WatchGuard ou pfSense."""
    s = sid()
    f = request.files.get("xml_file")
    if not f or not f.filename:
        return jsonify({"error": "Aucun fichier reçu"}), 400

    filename = secure_filename(f.filename)
    if not filename.lower().endswith(".xml"):
        return jsonify({"error": "Seuls les fichiers XML sont acceptés"}), 400

    tmp_path = os.path.join(session_dir(s), "_upload_tmp.xml")
    f.save(tmp_path)

    try:
        root = ET.parse(tmp_path).getroot()
        if root.tag not in ("profile", "pfsense"):
            os.remove(tmp_path)
            return jsonify({"error": "Fichier non reconnu (ni WatchGuard ni pfSense)"}), 400
    except ET.ParseError as e:
        os.remove(tmp_path)
        return jsonify({"error": f"XML invalide : {e}"}), 400

    # Remplace la config courante (fichier unique par session)
    base = get_base_xml(s)
    shutil.move(tmp_path, base)

    # Réinitialise le wizard de migration
    session.pop("mig_src", None)
    session.pop("mig_src_type", None)
    session.pop("mig_src_name", None)

    return redirect(url_for("index"))


@app.route("/export")
@login_required
def export():
    """Télécharge le XML actif (modifié ou original)."""
    s = sid()
    src = get_working_xml()
    if not src:
        return jsonify({"error": "Aucune configuration chargée"}), 404
    return send_file(src, as_attachment=True, download_name="firewall_netmorph.xml")


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/pick_source", methods=["GET"])
@login_required
def pick_source():
    """
    Étape 1 du wizard de migration.
    Détecte le type du XML courant et le stocke en session.
    """
    s = sid()
    xml_path = get_working_xml()
    if not xml_path:
        return jsonify({"error": "Aucune configuration chargée. Importez d'abord un fichier XML."}), 400

    try:
        root = ET.parse(xml_path).getroot()
        if root.tag == "profile":
            detected = "WatchGuard"
        elif root.tag == "pfsense":
            detected = "pfSense"
        else:
            return jsonify({"error": "Fichier non reconnu"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    session["mig_src"]      = xml_path
    session["mig_src_type"] = detected
    session["mig_src_name"] = os.path.basename(xml_path)

    return jsonify({"ok": True, "src_type": detected, "src_name": os.path.basename(xml_path)})


@app.route("/api/migrate", methods=["POST"])
@login_required
def migrate():
    """
    Étape 2 du wizard : lance la migration vers la marque cible.
    Body JSON : { "dest": "pfSense" | "WatchGuard" }
    """
    s = sid()
    data = request.get_json(force=True) or {}
    dest_type = data.get("dest", "").strip()

    src_path = session.get("mig_src")
    src_type = session.get("mig_src_type")

    if not src_path or not src_type:
        return jsonify({"error": "Étape 1 non complétée. Appelez /api/pick_source d'abord."}), 400
    if not dest_type:
        return jsonify({"error": "Destination manquante (dest)"}), 400
    if dest_type == src_type:
        return jsonify({"error": f"Source et destination sont toutes deux {src_type}."}), 400

    TEMPLATE_MAP = {
        "WatchGuard": os.path.join(template_dir(), "template", "Template_Firebox.xml"),
        "pfSense":    os.path.join(template_dir(), "template", "Template_pfsense.xml"),
    }
    tgt_path = TEMPLATE_MAP.get(dest_type)
    if not tgt_path or not os.path.exists(tgt_path):
        return jsonify({"error": f"Template {dest_type} introuvable"}), 500

    try:
        report = perform_migration(src_path, tgt_path)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception:
        return jsonify({"error": traceback.format_exc()}), 500

    # engine.py a écrit le résultat dans app_dir()/firewall.xml (fichier unique).
    session.pop("mig_src", None)
    session.pop("mig_src_type", None)
    session.pop("mig_src_name", None)

    return jsonify({
        "ok": True,
        "direction": f"{src_type} → {dest_type}",
        "count":    report.get("count", 0),
        "vlans":    len(report.get("vlans", [])),
        "aliases":  len(report.get("aliases", [])),
        "skipped":  report.get("skipped", 0),
        "warnings": report.get("warnings", [])[:5],
        "rules":    report.get("rules", [])[:12],
    })


@app.route("/api/reset_migration", methods=["POST"])
@login_required
def reset_migration():
    session.pop("mig_src", None)
    session.pop("mig_src_type", None)
    session.pop("mig_src_name", None)
    return jsonify({"ok": True})


@app.route("/api/add_rule", methods=["POST"])
@login_required
def add_rule():
    """
    Injecte une règle dans le XML actif.
    Accepte les mêmes paramètres qu'App_V2 (QueryString ou JSON).
    """
    s = sid()
    xml_path = get_working_xml()
    if not xml_path:
        return jsonify({"error": "Aucune configuration chargée"}), 400

    # Paramètres : JSON ou form
    args = request.get_json(force=True) or request.form.to_dict()

    try:
        save_rule_xml(args)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/add_interface", methods=["POST"])
@login_required
def add_interface():
    """Injecte une interface ou un VLAN dans le XML actif."""
    s = sid()
    xml_path = get_working_xml()
    if not xml_path:
        return jsonify({"error": "Aucune configuration chargée"}), 400

    args = request.get_json(force=True) or request.form.to_dict()

    try:
        save_interface_xml(args)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_rule", methods=["POST"])
@login_required
def api_delete_rule():
    """Supprime une règle par son nom."""
    s = sid()
    xml_path = get_working_xml()
    if not xml_path:
        return jsonify({"error": "Aucune configuration chargée"}), 400

    args = request.get_json(force=True) or {}
    rule_name = args.get("rule_name", "")

    try:
        delete_rule_xml(rule_name)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit")
@login_required
def api_audit():
    """Retourne les findings d'audit en JSON."""
    s = sid()
    xml_path = get_working_xml()
    if not xml_path:
        return jsonify({"error": "Aucune configuration chargée"}), 400
    try:
        findings = run_audit(xml_path)
        return jsonify(findings or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Dev server ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(os.path.join(app_dir(), "uploads"), exist_ok=True)
    app.run(debug=True, host="0.0.0.0", port=5000)
