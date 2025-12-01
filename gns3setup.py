#!/usr/bin/env python3
"""
Automatisches Tool zum Anlegen von Benutzern in GNS3 über die REST-API

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
import random
import string
from mail import MailClient
from datetime import datetime

# Debug-Einstellungen
DEFAULT_TIMEOUT = 10
VERIFY_TLS = True
LOG_FILE = "gns3_api_tool.log"

class Setup:
    def __init__(self):
        # Logdatei beginnen
        self.log_start()
        self.log("🚀 Starte GNS3 API Tool")

        # config.ini Datei laden
        self.cfg = self.load_config()

        # Login-versuch zum gns3-server
        self.login_result = self.login()
        self.headers = self.build_headers(self.login_result)
        self.session = self.login_result["session"]


    # Logging
    @staticmethod
    def log_start():
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\nLauf gestartet am {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    @staticmethod
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

    @staticmethod
    def pause_exit():
        input("\n✅ Vorgang abgeschlossen. Drücke eine beliebige Taste zum Beenden...")

    def load_config(self, path="config.ini"):
        if not os.path.exists(path):
            self.log(f"Konfigurationsdatei '{path}' wurde nicht gefunden.", is_error=True)
            self.pause_exit()
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
            self.log(f"Fehlender Eintrag in config.ini: {e}", is_error=True)
            self.pause_exit()
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
    def login(self):
        url = f"http://{self.cfg["host"]}/v3/access/users/authenticate"

        payload = {
            "username": self.cfg["login_user"],
            "password": self.cfg["login_pass"]
            }

        headers = {"Content-Type": "application/json"}

        self.log(f"🔐 Anmeldeversuch bei {self.cfg["host"]} als '{self.cfg["login_user"]}' ...")
        session = requests.Session()

        try:
            resp = session.post(url, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Login-Fehler: {e}", is_error=True)
            self.pause_exit()
            sys.exit(1)

        if not resp.ok:
            self.log(f"Login fehlgeschlagen: {resp.status_code} {resp.text}", is_error=True)
            self.pause_exit()
            sys.exit(1)

        try:
            raw = resp.json()
        except Exception:
            raw = {}

        token = raw.get("token") or raw.get("access_token")
        if token:
            self.log("✅ GNS3-Server Login erfolgreich (Token erhalten).")
            return {"session": session, "token": token}
        else:
            self.log("✅ GNS3-Server Login erfolgreich (Session-Cookie wird verwendet).")
            return {"session": session}

    @staticmethod
    def build_headers(login_result):
        headers = {"Content-Type": "application/json"}
        if "token" in login_result:
            headers["Authorization"] = f"Bearer {login_result['token']}"
        return headers

    def create_users_from_csv(self, mailman: MailClient = None):
        """
        Liest Benutzer aus einer CSV-Datei mit Kopfzeile ein (getrennt durch ; oder ,)
        und erstellt neue Benutzer in GNS3.

        Erwartete Spaltennamen (Groß-/Kleinschreibung egal):
            Benutzername, Vorname, Nachname, E-Mail

        Passwort wird automatisch als username + "123" gesetzt.
        """
        csv_path = self.cfg["csv_path"]
        host = self.cfg["host"]
        if not os.path.exists(csv_path):
            self.log(f"CSV-Datei '{csv_path}' wurde nicht gefunden.", is_error=True)
            self.pause_exit()
            sys.exit(1)

        self.log(f"📄 Lese Benutzer aus '{csv_path}' ...")

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
                self.log("❌ CSV-Datei ist leer oder ungültig.", is_error=True)
                self.pause_exit()
                sys.exit(1)

            # Debug: zeige erkannte Spalten
            self.log(f"📑 Erkannte Spalten: {headers}")

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
                self.log("❌ Eine oder mehrere erwartete Spalten fehlen in der CSV.", is_error=True)
                self.log(f"Gefundene Spalten: {headers}", is_error=True)
                self.pause_exit()
                sys.exit(1)
            
            # Role Id der ROlle "User" 
            role_id_user = self.get_role_id_user()

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
                self.log(f"👤 Erstelle Benutzer '{username}' ({fullname}) ...")
                user_id = self.create_user(user_payload)
                if user_id == False:
                    fail += 1
                    continue
                # TODO evtl mehr sleeps falls database (serverseitig) zu langsam
                #time.sleep(0.2)

                # Ressource Pool für Benutzer anlegen
                pool_id = self.create_ressource_pool(username+"_pool")
                # ACE Eintrag erstellen, damit dem User der Zugriff auf seinen
                # Pool mit "User-Role"-Rechteverteilung gegeben wird
                self.create_ace(pool_id, user_id, role_id_user)
                if pool_id == False:
                    continue
                # Projekte erstellen und direkt dem benutzereigenen Pool hinzufügen
                db_error = False
                for i in range(int(self.cfg["anzahl_projekte"])):
                    # Projekt "user_project1" bis x wird angelegt
                    if not db_error:
                        #code = ''.join(random.choices(string.ascii_lowercase, k=2))
                        #project_id = self.create_project(username+"_project_"+code+"_"+str(i+1))
                        project_id = self.create_project(username+"_project_"+str(i+1))
                        if project_id == False:
                            continue
                    else:
                        # neuen pool erstellen mit "uniqe" name
                        # test nur projekt code zeichen einfügen
                        code = ''.join(random.choices(string.ascii_lowercase, k=2))
                        project_id = self.create_project(username+"_project_"+code+"_"+str(i+1))
                    db_status = self.allocate_project_to_pool(project_id, pool_id)
                    # Database error abfang
                    if db_status == "och nee nicht der database error":
                        db_error = True
                        # neuen pool erstellen mit "uniqe" name
                        # test nur projekt code zeichen einfügen
                        code = ''.join(random.choices(string.ascii_lowercase, k=2))
                        project_id = self.create_project(username+"_project_"+code+"_"+str(i+1))
                        db_status = self.allocate_project_to_pool(project_id, pool_id)
                        if db_status == "och nee nicht der database error":
                            # extrem unwahrscheinlicher fall, dass genau dieser
                            # name auf genau diesem server bereits existiert hat
                            self.log("hilfe", is_error=True)
                            continue

                # Email versenden bei Option eingeschaltet
                if mailman is not None:
                    mailman.send_account_mail(
                        to=email,
                        name=fullname,
                        account=username,
                        password=password
                    )
                # Wenn bis hier alles lief, wurde Nutzer erfolgreich mit Pool+Prj angelegt
                success += 1

        self.log("\nBenutzer erstellt:")
        self.log(f"✅ Erfolgreich: {success}")
        self.log(f"❌ Fehlgeschlagen: {fail}")
        return success, fail

    def create_user(self, user_payload):
        """
        Erstellt User: Gibt User_ID zurück
        """
        create_path = "/v3/access/users"
        url = f"http://{self.cfg["host"]}{create_path}"

        try:
            resp = self.session.post(url, json=user_payload, headers=self.headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Verbindungsfehler: {e}", is_error=True)
            return False

        if resp.status_code in (200, 201):
            self.log(f"   ✅ Benutzer erfolgreich angelegt.")
            user_id = resp.json().get("user_id")
            return user_id
        else:
            self.log(resp.json(), is_error=True)
            return False

    def create_ressource_pool(self, name: str):
        create_path = "/v3/pools"
        url = f"http://{self.cfg["host"]}{create_path}"
        scheme = {
            "name": name
        }
        try:
            resp = self.session.post(url, json=scheme, headers=self.headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Verbindungsfehler: {e}", is_error=True)
            return False

        if resp.status_code in (200, 201):
            #log(resp.json())
            self.log(f"   ✅ Pool {name} angelegt")
            pool_id = resp.json().get("resource_pool_id")
            return pool_id
        else:
            self.log(resp.json(), is_error=True)
            return False

    def create_project(self, name: str):
        create_path = "/v3/projects"
        url = f"http://{self.cfg["host"]}{create_path}"

        scheme = {
            "name": name
        }

        try:
            resp = self.session.post(url, json=scheme, headers=self.headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Verbindungsfehler: {e}", is_error=True)
            return False

        if resp.status_code in (200, 201):
            #log(resp.json())
            self.log(f"   ✅ Projekt {name} angelegt")
            project_id = resp.json().get("project_id")
            return project_id
        else:
            self.log(resp.json(), is_error=True)
            return False

    def allocate_project_to_pool(self, project_id: str, pool_id: str):
        path = ("/v3/pools/"+pool_id+"/resources/"+project_id)
        url = f"http://{self.cfg["host"]}{path}"

        try:
            resp = self.session.put(url, headers=self.headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Verbindungsfehler: {e}", is_error=True)
            return False

        if resp.status_code == 204:
            self.log(f"   ✅ Projekt {project_id} zu Pool {pool_id} hinzugefügt")
            return True
        elif resp.status_code == 500:
            self.log(resp.json(), is_error=True)
            if resp.json().get("message")=="Database error detected, please check logs to find details":
                return "och nee nicht der database error"
        else:
            self.log(resp.json(), is_error=True)
            return False

    def create_ace(self, endpoint_pool_id, user_id, role_id):
        """
        Es wird ein ACL Eintrag erstellt: Dem User mit der UserID wird der Pfad seines
        erstellten Pools mit der Berechtigungsrolle "User" zugeteilt
        """
        path = ("/v3/access/acl")
        url = f"http://{self.cfg["host"]}{path}"

        scheme = {
            "ace_type": "user",
            # poolverzeichnis als endpoint
            "path": ("/pools/"+endpoint_pool_id),
            "propagate": True,
            "allowed": True,
            "user_id": user_id,
            "role_id": role_id
        }

        try:
            resp = self.session.post(url, json=scheme, headers=self.headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Verbindungsfehler: {e}", is_error=True)
            return False

        if resp.status_code == 201:
            self.log(f"   ✅ Berechtigung für Ressourcepool gesetzt")
            return True
        else:
            self.log(resp.json(), is_error=True)
            return False

    def get_role_id_user(self):
        def get_role_id_by_name(roles, target_role):
            for role in roles:
                if role.get("name") == target_role:
                    self.log(f"   ✅ Gefundene Rolle: {target_role} -> {role['role_id']}")
                    return role["role_id"]
            self.log(f"Rolle '{target_role}' nicht gefunden!", is_error=True)
            return None
        
        path = ("/v3/access/roles")
        url = f"http://{self.cfg["host"]}{path}"

        try:
            resp = self.session.get(url, headers=self.headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Verbindungsfehler: {e}", is_error=True)
            return False
        
        if resp.status_code == 200:
            role_id = get_role_id_by_name(resp.json(), "User")
            return role_id
        else:
            self.log(resp.json(), is_error=True)
            return False
        
    def check_pools(self,h):
        path = ("/v3/pools/")+h+"/resources"
        url = f"http://{self.cfg["host"]}{path}"

        try:
            resp = self.session.get(url, headers=self.headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_TLS)
        except requests.RequestException as e:
            self.log(f"Verbindungsfehler: {e}", is_error=True)
            return False
        
        if resp.status_code == 200:
            self.log(resp.json())

            return True
        else:
            self.log(resp.json(), is_error=True)
            return False
