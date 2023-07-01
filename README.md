# undertheradar

**Simple scripts I tinkered with that afford the pentester AV bypass options for l00ting the stuff you need**

## PSshell.ps1
Allows the pentester a means of executing commands on the remote machine via Powershell's `Invoke-WmiMethod`

We take advantage of using SMB file access and simply tail the file that receives our command output using Notepad++.  
![undertheradar2](https://github.com/g3tsyst3m/undertheradar/assets/19558280/3e302c33-26da-4b89-b176-6dc945b25e77)

# Dumpy.py

**Dumps SAM and SYSTEM files from registry for offline cracking**

# prompt.py

**forces a windows username and password prompt to the victim's desktop and saves results to c:\users\public\creds.log**

- automatically determines the current logged in user's username for you
- Forces user to continue trying until they get the password right OR they hit the cancel button

![image](https://github.com/g3tsyst3m/undertheradar/assets/19558280/93e0d37b-1f96-4221-9be9-b72db3198adb)


# collecttheloot.py

**Just a rough draft of me learning some logon winapi stuff using python.**

this script attempts to find passwords in your chrome browser and within your wifi passwords and then tests them to see if any are valid.  Does some other stuff too like check group memebership and OS version.  
`Depends on decryptbrowser.py`

# simplekeylogger

A very basic, stay under the radar keylogger!
![keylogger](https://github.com/g3tsyst3m/undertheradar/assets/19558280/9cc9cb62-d6a9-4b69-af19-ebbbc7a69dfb)
