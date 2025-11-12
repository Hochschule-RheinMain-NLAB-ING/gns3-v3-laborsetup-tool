import gns3setup as gs
from mail import MailClient

def main():
    # Logdatei beginnen
    gs.log_start()
    gs.log("🚀 Starte GNS3 API Tool...")

    # config.ini laden    
    cfg = gs.load_config()

    # login-versuch zum gns3-server
    login_result = gs.login(cfg["host"], cfg["login_user"], cfg["login_pass"])

    # login-versuch zum email-server
    mailman = MailClient(cfg["email_server"], cfg["email_port"], cfg["email"], cfg["email_pw"])
    mailman.login()
    #
    mailman.send_account_mail(
        to="max95.0@gmx.de",
        name = "idiot",
        account="flachwixer",
        password="passowrd123"
    )
    #
    
    #gs.create_users_from_csv(cfg, login_result)

    gs.log("🏁 Vorgang beendet. Details siehe Logdatei: gns3_api_tool.log")
    #pause_exit()

if __name__ == "__main__":
    main()
