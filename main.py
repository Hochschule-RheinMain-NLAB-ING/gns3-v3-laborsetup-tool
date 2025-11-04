#!/usr/bin/env python3
"""
gns3_api_tool.py
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
from datetime import datetime

# ==== Einstellungen ====
DEFAULT_TIMEOUT = 10
VERIFY_TLS = True  # False bei Self-Signed (nicht empfohlen)
LOG_FILE = "gns3_api_tool.log"

# ==== Logging ====
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
        csv_path = config["files"]["csv_path"]
        create_path = config["files"].get("create_path", "/v3/access/users")
    except KeyError as e:
        log(f"Fehlender Eintrag in config.ini: {e}", is_error=True)
        pause_exit()
        sys.exit(1)

    return {
        "host": host.strip(),
        "login_user": login_user.strip(),
        "login_pass": login_pass.strip(),
        "csv_path": csv_path.strip(),
        "create_path": create_path.strip()
    }

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
        log("✅ Login erfolgreich (Token erhalten).")
        return {"session": s, "token": token}
    else:
        log("✅ Login erfolgreich (Session-Cookie wird verwendet).")
        return {"session": s}

def build_headers(login_result):
    headers = {"Content-Type": "application/json"}
    if "token" in login_result:
        headers["Authorization"] = f"Bearer {login_result['token']}"
    return headers

def create_user(host, login_result, user_payload, create_path):
    url = f"http://{host}{create_path}"
    headers = build_headers(login_result)
    session = login_result["session"]

    try:
        resp = session.post(url, json=user_payload, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        return False, f"Verbindungsfehler: {e}"

    if resp.status_code in (200, 201):
        return True, resp.json()
    else:
        try:
            err = resp.json()
        except:
            err = resp.text
        return False, err

def create_users_from_csv(cfg, login_result):
    csv_path = cfg["csv_path"]
    if not os.path.exists(csv_path):
        log(f"CSV-Datei '{csv_path}' wurde nicht gefunden.", is_error=True)
        pause_exit()
        sys.exit(1)

    log(f"📄 Lese Benutzer aus '{csv_path}' ...")
    success = 0
    fail = 0

    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            username = row.get("username")
            if not username:
                continue

            log(f"👤 Erstelle Benutzer '{username}' ...")
            ok, result = create_user(cfg["host"], login_result, row, cfg["create_path"])
            if ok:
                log(f"   ✅ Benutzer '{username}' erfolgreich angelegt.")
                success += 1
            else:
                log(f"   ❌ Fehler bei '{username}': {result}", is_error=True)
                fail += 1
            time.sleep(0.2)  # kleine Pause zur Entlastung des Servers

    log("\n===== Zusammenfassung =====")
    log(f"✅ Erfolgreich: {success}")
    log(f"❌ Fehlgeschlagen: {fail}")
    return success, fail

def create_test_user(host, login_result):
    create_path = "/v3/access/users"
    url = f"http://{host}{create_path}"
    headers = build_headers(login_result)
    session = login_result["session"]
    
    new_user = {
    "username": "testuser2",
    "is_active": "true",
    "email": "testuser2@example.com",
    "fullname": "Test User1",
    "password": "user1234",
    }

    try:
        resp = session.post(url, json=new_user, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
    except requests.RequestException as e:
        return False, f"Verbindungsfehler: {e}"

    if resp.status_code in (200, 201):
        log(resp.json())
        return True, resp.json()
    else:
        try:
            err = resp.json()
        except:
            err = resp.text
        log(resp.json())
        return False, err


def main():
    # Logdatei mit Header beginnen
    log_start()
    log("🚀 Starte GNS3 API Tool...")

    # config.ini laden    
    cfg = load_config()
    # login-versuch zum gns3-server
    login_result = login(cfg["host"], cfg["login_user"], cfg["login_pass"])
    # login-versuch zum email- ding
    # create_users_from_csv(cfg, login_result)
    # test user create
    create_test_user(cfg["host"], login_result)

    log("🏁 Vorgang beendet. Details siehe Logdatei: gns3_api_tool.log")
    #pause_exit()

if __name__ == "__main__":
    main()
