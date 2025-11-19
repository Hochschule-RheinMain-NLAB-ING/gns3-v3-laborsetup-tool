#!/usr/bin/env python3
"""
Automatisches Tool zum Anlegen von Benutzern in GNS3 über die REST-API.

Ablauf:
1. Konfiguration aus config.ini lesen
2. Login durchführen
3. Benutzer aus CSV-Datei anlegen
4. Statusmeldungen in Konsole + Fehler in Logdatei schreiben
5. Auf Tastendruck beenden
"""

import requests
import csv
import time
import sys
import os
import configparser
from mail import MailClient
from datetime import datetime

# Debug-Einstellungen
DEFAULT_TIMEOUT = 10
VERIFY_TLS = True
LOG_FILE = "gns3_api_tool.log"

# Logging
def log_start():
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n=== Lauf gestartet am {} ===\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

def log(msg: str, is_error: bool = False):
    """Schreibt eine Meldung mit Zeitstempel in die Logdatei."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {'ERROR' if is_error else 'INFO'}: {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)
    # In Konsole nur kurz anzeigen (Fehler farbig)
    if is_error:
        print(f"❌ {msg}")
    else:
        print(msg)

def pause_exit():
    input("\n✅ Vorgang abgeschlossen. Drücke eine beliebige Taste zum Beenden...")

def load_config(path="config.ini"):
    if not os.path.exists(path):
        log(f"Konfigurationsdatei '{path}' wurde nicht gefunden.", is_error=True)
        pause_exit()
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(path, encoding="utf-8")

    try:
        host = config["gns3"]["host"]
        login_user = config["gns3"]["login_user"]
        login_pass = config["gns3"]["login_pass"]
        anzahl_projekte = config["gns3"]["anzahl_projekte"]
        csv_path = config["files"]["csv_path"]
        create_path = config["files"]["create_path"]
        email = config["email"]["email_adresse"]
        email_pw = config["email"]["email_pass"]
        email_server = config["email"]["smtp"]
        email_port = config["email"]["port"]
        email_option = config["email"]["email_option"]
    except KeyError as e:
        log(f"Fehlender Eintrag in config.ini: {e}", is_error=True)
        pause_exit()
        sys.exit(1)

    return {
        "host": host.strip(),
        "login_user": login_user.strip(),
        "login_pass": login_pass.strip(),
        "csv_path": csv_path.strip(),
        "create_path": create_path.strip(),
        "anzahl_projekte": anzahl_projekte.strip(),
        "email": email.strip(),
        "email_pw": email_pw.strip(),
        "email_server": email_server.strip(),
        "email_port": email_port.strip(),
        "email_option": email_option.strip()
    }

# Login funktionen
def login(host: str, username: str, password: str):
    url = f"http://{host}/v3/access/users/authenticate"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}

    log(f"🔐 Melde an bei {host} als '{username}' ...")
    s = requests.Session()

    try:
        resp = s.post(url, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        log(f"Login-Fehler: {e}", is_error=True)
        pause_exit()
        sys.exit(1)

    if not resp.ok:
        log(f"Login fehlgeschlagen: {resp.status_code} {resp.text}", is_error=True)
        pause_exit()
        sys.exit(1)

    try:
        raw = resp.json()
    except Exception:
        raw = {}

    token = raw.get("token") or raw.get("access_token")
    if token:
        log("✅ GNS3-Server Login erfolgreich (Token erhalten).")
        return {"session": s, "token": token}
    else:
        log("✅ GNS3-Server Login erfolgreich (Session-Cookie wird verwendet).")
        return {"session": s}

def build_headers(login_result):
    headers = {"Content-Type": "application/json"}
    if "token" in login_result:
        headers["Authorization"] = f"Bearer {login_result['token']}"
    return headers

def create_users_from_csv(cfg, login_result, mailman: MailClient = None):
    """
    Liest Benutzer aus einer CSV-Datei mit Kopfzeile ein (getrennt durch ; oder ,)
    und erstellt neue Benutzer in GNS3.

    Erwartete Spaltennamen (Groß-/Kleinschreibung egal):
        Benutzername, Vorname, Nachname, E-Mail

    Passwort wird automatisch als username + "123" gesetzt.
    """
    csv_path = cfg["csv_path"]
    host = cfg["host"]
    if not os.path.exists(csv_path):
        log(f"CSV-Datei '{csv_path}' wurde nicht gefunden.", is_error=True)
        pause_exit()
        sys.exit(1)

    log(f"📄 Lese Benutzer aus '{csv_path}' ...")

    success = 0
    fail = 0

    # Versuche zuerst mit Semikolon, sonst mit Komma
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        # Versuche Delimiter zu erraten
        sample = csvfile.read(1024)
        csvfile.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=";,")
        reader = csv.reader(csvfile, dialect)

        headers = next(reader, None)
        if not headers:
            log("❌ CSV-Datei ist leer oder ungültig.", is_error=True)
            pause_exit()
            sys.exit(1)

        # Debug: zeige erkannte Spalten
        log(f"📑 Erkannte Spalten: {headers}")

        def find_index(name):
            for i, h in enumerate(headers):
                if h.strip().lower() == name.lower():
                    return i
            return None

        idx_username = find_index("Benutzername")
        idx_vorname = find_index("Vorname")
        idx_nachname = find_index("Nachname")
        idx_email = find_index("E-Mail")

        if None in (idx_username, idx_vorname, idx_nachname, idx_email):
            log("❌ Eine oder mehrere erwartete Spalten fehlen in der CSV.", is_error=True)
            log(f"Gefundene Spalten: {headers}", is_error=True)
            pause_exit()
            sys.exit(1)

        for row in reader:
            # Leere Zeilen überspringen
            if not row or len(row) < max(idx_email, idx_nachname, idx_vorname, idx_username) + 1:
                continue

            username = row[idx_username].strip()
            vorname = row[idx_vorname].strip()
            nachname = row[idx_nachname].strip()
            email = row[idx_email].strip()

            if not username:
                continue

            fullname = f"{vorname} {nachname}".strip()
            password = f"{username}123"

            user_payload = {
                "username": username,
                "is_active": True,
                "email": email,
                "full_name": fullname,
                "password": password
            }
            # Benutzer anlegen
            log(f"👤 Erstelle Benutzer '{username}' ({fullname}) ...")
            result = create_user(host, login_result, user_payload)
            if result != False:
                log(f"   ✅ Benutzer '{username}' erfolgreich angelegt.")
            else:
                log(f"   ❌ Fehler bei '{username}': {result}", is_error=True)
                fail += 1
                continue
            # TODO evtl mehr sleeps falls database (serverseitig) zu langsam
            time.sleep(0.2)

            # Ressource Pool für Benutzer anlegen
            pool_id = create_ressource_pool(host, login_result, (username+"_pool"))
            if pool_id == False:
                continue
            # Projekte erstellen und direkt dem benutzereigenen Pool hinzufügen
            for i in range(int(cfg["anzahl_projekte"])):
                # Projekt "user_project1" bis x wird angelegt
                project_id = create_project(host, login_result, (username+"_project"+str(i)))
                if project_id == False:
                    continue
                allocate_project_to_pool(host, login_result, project_id, pool_id)

            # Email versenden bei Option eingeschaltet
            if mailman is not None:
                mailman.send_account_mail(
                    # TODO entfernen debug email
                    to="max95.0@gmx.de",
                    name=fullname,
                    account=username,
                    password=password
                )
            # Wenn bis hier alles lief, wurde Nutzer erfolgreich mit Pool+Prj angelegt
            success += 1

    log("\n===== Zusammenfassung =====")
    log(f"✅ Erfolgreich: {success}")
    log(f"❌ Fehlgeschlagen: {fail}")
    return success, fail

def create_user(host: str, login_result, user_payload):
    create_path = "/v3/access/users"
    url = f"http://{host}{create_path}"
    headers = build_headers(login_result)
    session = login_result["session"]

    try:
        resp = session.post(url, json=user_payload, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        log(f"Verbindungsfehler: {e}", is_error=True)
        return False

    if resp.status_code in (200, 201):
        log(f"   ✅ Benutzer erfolgreich angelegt.")
        user_id = resp.json().get("user_id")
        return user_id
    else:
        log("Etwas ist schiefgelaufen: ", is_error=True)
        log(resp.json(), is_error=True)
        return False

def create_ressource_pool(host: str, login_result, name: str):
    create_path = "/v3/pools"
    url = f"http://{host}{create_path}"
    headers = build_headers(login_result)
    session = login_result["session"]

    scheme = {
        "name": name
    }

    try:
        resp = session.post(url, json=scheme, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        log(f"Verbindungsfehler: {e}", is_error=True)
        return False

    if resp.status_code in (200, 201):
        #log(resp.json())
        log(f"Pool {name} angelegt")
        pool_id = resp.json().get("resource_pool_id")
        return pool_id
    else:
        log("Etwas ist schiefgelaufen: ", is_error=True)
        log(resp.json(), is_error=True)
        return False

def create_project(host: str, login_result, name: str):
    create_path = "/v3/projects"
    url = f"http://{host}{create_path}"
    headers = build_headers(login_result)
    session = login_result["session"]

    scheme = {
        "name": name
    }

    try:
        resp = session.post(url, json=scheme, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        log(f"Verbindungsfehler: {e}", is_error=True)
        return False

    if resp.status_code in (200, 201):
        #log(resp.json())
        log(f"Projekt {name} angelegt")
        project_id = resp.json().get("project_id")
        return project_id
    else:
        log("Etwas ist schiefgelaufen: ", is_error=True)
        log(resp.json(), is_error=True)
        return False

def allocate_project_to_pool(host: str, login_result, project_id: str, pool_id: str) -> bool:
    path = ("/v3/pools/"+pool_id+"/resources/"+project_id)
    url = f"http://{host}{path}"
    headers = build_headers(login_result)
    session = login_result["session"]

    try:
        resp = session.put(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        log(f"Verbindungsfehler: {e}", is_error=True)
        return False

    if resp.status_code == 204:
        log(f"Projekt {project_id} zu Pool {pool_id} hinzugefügt")
        return True
    else:
        log("Etwas ist schiefgelaufen: ", is_error=True)
        log(resp.json(), is_error=True)
        return False

def create_ace(host: str, login_result, endpoint_pool_id, user_id, role_id):
    """
    Es wird ein ACL Eintrag erstellt: Dem User mit der UserID wird der Pfad seines
    erstellten Pools mit der Berechtigungsrolle "User" zugeteilt
    """
    path = ("/v3/access/acl")
    url = f"http://{host}{path}"
    headers = build_headers(login_result)
    session = login_result["session"]
    # poolverzeichnis als endpoint

    scheme = {
        "ace_type": "user",
        "path": ("/pools/"+endpoint_pool_id),
        "propagate": True,
        "allowed": True,
        "user_id": user_id,
        "role_id": role_id
    }

    try:
        resp = session.get(url, json=scheme, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        log(f"Verbindungsfehler: {e}", is_error=True)
        return False

    if resp.status_code == 200:
        log(f"Prefügt")
        return True
    else:
        log("Etwas ist schiefgelaufen: ", is_error=True)
        log(resp.json(), is_error=True)
        return False

def get_role_id_user(host: str, login_result):
    path = ("/v3/access/roles")
    url = f"http://{host}{path}"
    headers = build_headers(login_result)
    session = login_result["session"]

    try:
        resp = session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        log(f"Verbindungsfehler: {e}", is_error=True)
        return False
    
    if resp.status_code == 200:
        role_id = get_role_id_by_name(resp.json(), "User")
        return role_id
    else:
        log("Etwas ist schiefgelaufen: ", is_error=True)
        log(resp.json(), is_error=True)
        return False

def get_role_id_by_name(roles, target_name):
    for role in roles:
        if role.get("name") == target_name:
            log(f"Gefundene Rolle: {target_name} -> {role['role_id']}")
            return role["role_id"]
    log(f"❌ Rolle '{target_name}' nicht gefunden!", is_error=True)
    return None
