import gns3setup as gs
from mail import MailClient

def main():
    setup = gs.Setup()
    if setup.cfg["email_option"] == "true":
        # Login-versuch zum email-server
        mailman = MailClient(setup.cfg["email_server"], setup.cfg["email_port"], 
                             setup.cfg["email"], setup.cfg["email_pw"])
        login_status = mailman.login()
        if not login_status:
            # Falls der Email login failed, meldung 
            # ob man email lieber deaktivieren will
            setup.log("Es gab ein Problem beim Einloggen zum Emailserver")
            return
        # Hauptablauf .csv Tabelle einlesen
        setup.create_users_from_csv(mailman)
    else:
        # Hauptablauf .csv Tabelle einlesen OHNE MAIL
        setup.create_users_from_csv()

    setup.log("🏁 Vorgang beendet. Details siehe Logdatei: gns3_api_tool.log")
    setup.pause_exit()

if __name__ == "__main__":
    main()
