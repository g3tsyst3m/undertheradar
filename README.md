# undertheradar

**Simple scripts I worked on that afford the pentester AV bypass options for l00ting the stuff you need**

## PSshell.ps1
Allows the pentester a means of executing commands on the remote machine via Powershell's `Invoke-WmiMethod`

We take advantage of using SMB file access and simply tail the file that receives our command output using Notepad++.  
![undertheradar](https://github.com/g3tsyst3m/undertheradar/assets/19558280/0ea085e0-ed5f-4bfa-aeca-997263be000d)

# Dumpy.py

**Dumps SAM and SYSTEM files from registry for offline cracking**

# collecttheloot.py

**Just a rough draft of me learning some logon winapi stuff using python.**

this script attempts to find passwords in your chrome browser and within your wifi passwords and then tests them to see if any are valid.  Does some other stuff too like check group memebership and OS version.  `Depends on decryptbrowser.py`
