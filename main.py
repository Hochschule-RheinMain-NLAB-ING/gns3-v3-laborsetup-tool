#!/usr/bin/env python3
"""
gns3_api_tool.py
Ein kleines Tool: Login + Benutzer erstellen (einzeln oder aus CSV).
Benutze: python gns3_api_tool.py --host HOST --login-user admin --login-pass secret --create-user newuser --create-pass pwd123
oder:  python gns3_api_tool.py --host HOST --login-user admin --login-pass secret --csv users.csv
"""

import requests
import argparse
import csv
import os
import sys
from typing import Optional, Dict, Any

# --- Konfiguration / Defaults ---
DEFAULT_TIMEOUT = 10  # Sekunden für HTTP-Requests
VERIFY_TLS = True     # auf False setzen für self-signed (nicht empfohlen)

# --- Hilfsfunktionen ---
def debug_print(msg: str):
    # Einfaches schaltbares Debug-Logging; hier immer an
    print(msg, file=sys.stderr)

def login(host: str, username: str, password: str, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS) -> Dict[str, Any]:
    """
    Login via JSON (POST /v3/access/users/authenticate).
    Liefert dict mit keys:
      - 'session' (requests.Session) falls Cookie-basiert
      - 'token' (str) falls Token zurückgegeben wurde
      - 'raw' (requests.Response.json()) Rohantwort
      - 'headers' falls spezielle Header nötig sind
    """
    url = f"http://{host}/v3/access/users/authenticate"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}
    s = requests.Session()
    debug_print(f"POST {url} -> payload: {payload}")
    resp = s.post(url, json=payload, headers=headers, timeout=timeout, verify=verify)
    resp.raise_for_status()
    raw = {}
    try:
        raw = resp.json()
    except ValueError:
        # keine JSON-Antwort
        raw = {"_text": resp.text}

    result = {"session": s, "raw": raw, "headers": {}}

    # Mögliche Token-Felder prüfen
    for key in ("token", "access_token", "auth_token"):
        if isinstance(raw, dict) and key in raw:
            result["token"] = raw[key]
            debug_print(f"Token field '{key}' detected.")
            return result

    # Manche APIs setzen einen Authorization Header in der Antwort
    if "Authorization" in resp.headers:
        result["headers"]["Authorization"] = resp.headers["Authorization"]
        debug_print("Authorization header in response detected.")
        return result

    # Cookie-basiert: Session hat Cookies (z. B. sessionid)
    if s.cookies:
        debug_print(f"Cookies received: {s.cookies.get_dict()}")
        return result

    # Fallback: versuche bestimmte Pfade in JSON, z.B. raw['data']['token']
    if isinstance(raw, dict):
        # rekursiv nach einem Wert suchen, der 'token' heißt
        def find_token(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k in ("token", "access_token", "auth_token"):
                        return v
                    t = find_token(v)
                    if t:
                        return t
            elif isinstance(d, list):
                for item in d:
                    t = find_token(item)
                    if t:
                        return t
            return None
        t = find_token(raw)
        if t:
            result["token"] = t
            debug_print("Token found by recursive search in JSON.")
            return result

    # sonst: raw zurückgeben (Caller muss adaptieren)
    debug_print("No explicit token found in response — returning session+raw for manual handling.")
    return result


def build_auth_headers(login_result: Dict[str, Any]) -> Dict[str, str]:
    """
    Erzeugt Header für weitere Requests.
    Priorität:
      1) 'token' -> Authorization: Bearer <token>
      2) login_result['headers'] falls gesetzt
      3) leer (Session-Cookie wird verwendet)
    """
    headers = {}
    if "token" in login_result:
        headers["Authorization"] = f"Bearer {login_result['token']}"
    headers.update(login_result.get("headers", {}))
    return headers


def create_user(host: str, login_result: Dict[str, Any], user_payload: Dict[str, Any], create_path: Optional[str]=None, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS):
    """
    Erzeugt einen Benutzer. create_path ist optional, z.B. '/v3/access/users'
    Wenn None, muss caller wissen, wie die eigentliche URL lautet.
    """
    if create_path is None:
        create_path = "/v3/access/users"  # häufige Route; anpassen wenn API anders ist
    url = f"http://{host}{create_path}"
    headers = {"Content-Type": "application/json"}
    headers.update(build_auth_headers(login_result))

    session: requests.Session = login_result.get("session")
    if session:
        resp = session.post(url, json=user_payload, headers=headers, timeout=timeout, verify=verify)
    else:
        resp = requests.post(url, json=user_payload, headers=headers, timeout=timeout, verify=verify)

    # Fehlerhandling
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        debug_print(f"Fehler beim Anlegen des Benutzers: {resp.status_code} {resp.text}")
        raise

    try:
        return resp.json()
    except ValueError:
        return {"_text": resp.text}


# --- CLI / Bulk CSV support ---
def process_csv_and_create(host, login_result, csv_path, create_path=None):
    created = []
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        # Erwartete Spalten beispielhaft: username,password,fullname,email,role
        for row in reader:
            payload = {k: v for k, v in row.items() if v != ""}
            debug_print(f"Creating user: {payload.get('username')}")
            try:
                res = create_user(host, login_result, payload, create_path=create_path)
                created.append((payload.get("username"), res))
            except Exception as e:
                debug_print(f"Fehler bei {payload.get('username')}: {e}")
    return created


# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser(description="Einfacher GNS3 API User-Creator")
    parser.add_argument("--host", required=True, help="host:port z.B. 127.0.0.1:3080")
    parser.add_argument("--login-user", required=True)
    parser.add_argument("--login-pass", required=True)
    parser.add_argument("--create-user", help="Benutzername zum Erstellen")
    parser.add_argument("--create-pass", help="Passwort")
    parser.add_argument("--fullname", help="Vollständiger Name")
    parser.add_argument("--email", help="Email")
    parser.add_argument("--csv", help="CSV-Datei mit Benutzern (username,password,...)")
    parser.add_argument("--create-path", help="API Pfad zum Anlegen von Benutzern (z. B. /v3/access/users)")
    args = parser.parse_args()

    login_result = login(args.host, args.login_user, args.login_pass)
    debug_print(f"Login raw response: {login_result.get('raw')}")

    if args.csv:
        results = process_csv_and_create(args.host, login_result, args.csv, create_path=args.create_path)
        for u, res in results:
            print(f"{u}: {res}")
        return

    if args.create_user:
        payload = {"username": args.create_user}
        if args.create_pass:
            payload["password"] = args.create_pass
        if args.fullname:
            payload["fullname"] = args.fullname
        if args.email:
            payload["email"] = args.email

        res = create_user(args.host, login_result, payload, create_path=args.create_path)
        print(res)
        return

    print("Keine Aktion angegeben. Siehe --help.")


if __name__ == "__main__":
    main()
