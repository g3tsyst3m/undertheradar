function shellcmds {
	Clear-Host
	Write-Host "*******************************"
	Write-Host "A Simple PSExec-esque utility ;)"
	Write-Host "*******************************"
	Write-Host ""
	Write-Host "Your command:"
	$myinput=Read-Host
	if ($myinput -eq "clear")
	{
	$arguments='powershell -command Clear-Content c:\users\public\output.txt'
	}
	else
	{
	$arguments='cmd.exe /c' + $myinput + ' >> c:\users\public\output.txt'
	}
	Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $arguments -ComputerName $ipcomputer -Credential $cred >> c:/users/public/troubleshooting_log.log
}

Write-Host "ip or computername:"
$ipcomputer=Read-Host
$cred=Get-Credential
while ($true)
{
shellcmds
}