"""
utils.py — NETMORPH SaaS (session-aware)
=========================================
Remplace le utils.py desktop par une version session-aware via threading.local.

Principe :
  Au début de chaque requête Flask, app.py appelle set_session_context(session_id).
  Cela fait en sorte que app_dir() et get_working_xml() retournent les chemins
  spécifiques à l'utilisateur — sans modifier engine.py.

  En dehors d'une requête (ex: init), app_dir() retourne le dossier réel de l'app.

Structure fichiers par session :
  uploads/<session_id>/firewall.xml — config unique (source de vérité)
"""

import os
import sys
import threading

# ── Dossier réel de l'application (calculé une fois à l'import) ───────────────
_REAL_APP_DIR: str = (
    os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)

_UPLOAD_ROOT: str = os.path.join(_REAL_APP_DIR, "uploads")

# ── Thread-local pour le contexte de session ──────────────────────────────────
_local = threading.local()


def set_session_context(session_id: str) -> None:
    """
    Définit le contexte de session pour le thread courant.
    À appeler en @app.before_request dans Flask.
    """
    _local.session_id = session_id


def clear_session_context() -> None:
    """Supprime le contexte de session (utile après la requête)."""
    _local.session_id = None


def _current_session_id() -> str | None:
    return getattr(_local, "session_id", None)


# ── Fonctions publiques ───────────────────────────────────────────────────────

def app_dir() -> str:
    """
    Retourne le dossier de travail courant.

    - Dans un contexte de requête Flask : uploads/<session_id>/
    - Hors contexte                     : dossier réel de l'app

    Engine.py appelle app_dir() pour lire/écrire firewall.xml.
    En rendant app_dir() session-aware ici, engine.py n'a pas besoin
    d'être modifié.
    """
    sid = _current_session_id()
    if sid:
        d = os.path.join(_UPLOAD_ROOT, sid)
        os.makedirs(d, exist_ok=True)
        return d
    return _REAL_APP_DIR


def template_dir() -> str:
    """
    Retourne TOUJOURS le dossier réel de l'app.
    Utilisé par app.py pour trouver template/Template_Firebox.xml etc.
    (Ces fichiers ne sont pas par session.)
    """
    return _REAL_APP_DIR


def get_working_xml() -> str | None:
    """
    Retourne le chemin du XML actif de la session courante.
    Un seul fichier par session : firewall.xml.
    Appelé par engine.py sans argument — fonctionne grâce à app_dir().
    """
    path = os.path.join(app_dir(), "firewall.xml")
    return path if os.path.exists(path) else None


def session_dir(session_id: str) -> str:
    """Retourne (et crée si besoin) le dossier de session explicite."""
    d = os.path.join(_UPLOAD_ROOT, session_id)
    os.makedirs(d, exist_ok=True)
    return d


def get_base_xml(session_id: str) -> str:
    return os.path.join(session_dir(session_id), "firewall.xml")


def get_modified_xml(session_id: str) -> str:
    """Compat : pointe sur firewall.xml (plus de fichier modifié séparé)."""
    return os.path.join(session_dir(session_id), "firewall.xml")


# ── XML helpers — inchangés vs App_V2 ────────────────────────────────────────

def safe_text(elem, tag):
    """Extrait le texte d'une balise XML sans crasher si elle n'existe pas."""
    if elem is None:
        return ""
    c = elem.find(tag)
    return (c.text or "").strip() if c is not None else ""


def resolve_wg_alias(root, alias_name):
    """Résout récursivement un alias WatchGuard vers une IP ou un réseau."""
    visited = set()

    def dive(name):
        if name in visited:
            return []
        visited.add(name)
        base_nets = ["Any-Trusted", "Any-External", "Any-Optional", "Any", "Firebox", "Any-BOVPN"]
        if name in base_nets:
            return [name]

        res = []
        for al in root.findall(".//alias-list/alias"):
            if safe_text(al, "name") == name:
                for mem in al.findall(".//alias-member-list/alias-member/alias-name"):
                    if mem.text:
                        res.extend(dive(mem.text))
                for mem_ip in al.findall(".//alias-member-list/alias-member/address"):
                    if mem_ip.text and mem_ip.text != "Any":
                        res.append(mem_ip.text)

        for ag in root.findall(".//address-group-list/address-group"):
            if safe_text(ag, "name") == name:
                ip = safe_text(ag, ".//host-ip-addr")
                if ip:
                    res.append(ip)
                net = safe_text(ag, ".//ip-network-addr")
                if net:
                    res.append(net)

        if not res:
            res = [name.replace(".snat", "")]
        return res

    results = list(set(dive(alias_name)))
    if "Any" in results or ("Any-External" in results and "Any-Trusted" in results):
        return "any"
    if "Any-External" in results:
        return "wan"
    if "Any-Trusted" in results:
        return "lan"
    if results:
        return results[0]
    return alias_name
