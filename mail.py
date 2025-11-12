import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import traceback

class MailClient:
    """
    Einfaches Modul zum Senden von E-Mails über SMTP
    """

    def __init__(self, smtp_server, smtp_port, username, password, use_tls=True):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.server = None

    def login(self):
        """Verbindet sich mit dem SMTP-Server und prüft Login.
           Gibt True/False zurück und zeigt Erfolg/Fehler an.
        """
        print(f"📧 Versuche Anmeldung bei {self.smtp_server}:{self.smtp_port} als {self.username} ...")

        try:
            if self.use_tls:
                context = ssl.create_default_context()
                self.server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                self.server.starttls(context=context)
            else:
                self.server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)

            self.server.login(self.username, self.password)
            print("✅ Email-Server Anmeldung erfolgreich.")
            return True

        except smtplib.SMTPAuthenticationError:
            print("❌ Email-Server Anmeldung fehlgeschlagen: Falsche Zugangsdaten.")
        except Exception as e:
            print(f"❌ Email-Server Fehler bei der Anmeldung: {e}")
            traceback.print_exc()

        return False

    def send_account_mail(self, to, name, account, password):
        """
        Sendet eine Mail an 'to' mit einer vordefinierten Vorlage.
        Die Parameter name, account und password werden automatisch eingefügt.
        """
        if not self.server:
            print("⚠️  Nicht angemeldet – bitte zuerst login() aufrufen!")
            return False

        subject = f"Ihr neuer GNS3-Account ({account})"
        from_addr = self.username
        to_addr = to

        # Mailvorlage, evtl aus cfg-Datei
        body = f"""
        Hallo {name},

        Ihr neuer Zugang für den GNS3-Server wurde eingerichtet.

        🔹 Benutzername: {account}
        🔹 Passwort: {password}

        Bitte ändern Sie das Passwort nach dem ersten Login.

        Mit freundlichen Grüßen  
        Ihr GNS3-Netzwerklabor-Setup-Tool
        """

        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            self.server.send_message(msg)
            print(f"📨 E-Mail erfolgreich an {to} gesendet.")
            return True
        except Exception as e:
            print(f"❌ Fehler beim Senden an {to}: {e}")
            traceback.print_exc()
            return False

    def close(self):
        """Verbindung zum SMTP-Server sauber beenden."""
        if self.server:
            try:
                self.server.quit()
                print("📭 Verbindung geschlossen.")
            except Exception:
                pass
            self.server = None
