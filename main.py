import gns3setup as gs
from mail import MailClient

def main():
    # Loginversuch zum GNS3 Server
    setup = gs.Setup()
    if setup.cfg["email_option"] == "true":
        # Loginversuch zum Email-Server
        mailman = MailClient(setup.cfg["email_server"], setup.cfg["email_port"], 
                             setup.cfg["email"], setup.cfg["email_pw"])
        login_status = mailman.login()
        if not login_status:
            # Falls der Email login failed, meldung
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
