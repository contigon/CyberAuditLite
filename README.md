# GoGetCyberAuditLite
The Script make a ZIP file that contains the CyberGatito script and the tools he runs to audit information from network.
The script take the tools and compress them into one zip file that you can insert into your internal network.
The CyberGatito tool will run the tools automatically and set a folder with all the outputs of the various tools.

To run the script run this command:
```powershell
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/maros17/GoGetCyberAuditLite/main/MakePackage.ps1')
```

After you extract all files on a computer in the internal network, you need to run this command to be able to run scripts in your computer:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```
Make sure to run this command under administrator permissions

After running this command, you can run the CyberGatito.ps1 script by administrator powershell session
