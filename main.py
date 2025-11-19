import gns3setup as gs
from mail import MailClient

def main():
    setup = gs.Setup()
    if True:
        setup.allocate_project_to_pool("f8f5bf87-d0b4-4a4f-9519-74694c2120bc","61767fe5-0543-4b6f-9f37-25c9da1f9d56")
        return
    if setup.cfg["email_option"] == "true":
        # Login-versuch zum email-server
        mailman = MailClient(setup.cfg["email_server"], setup.cfg["email_port"], 
                             setup.cfg["email"], setup.cfg["email_pw"])
        mailman.login()

        # Hauptablauf .csv Tabelle einlesen
        setup.create_users_from_csv(mailman)
    else:
        # Hauptablauf .csv Tabelle einlesen OHNE MAIL
        setup.create_users_from_csv()

    setup.log("🏁 Vorgang beendet. Details siehe Logdatei: gns3_api_tool.log")
    #pause_exit()

if __name__ == "__main__":
    main()
