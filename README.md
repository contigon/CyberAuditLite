# CyberAuditLite

## MakePackage.ps1
The Script makes a ZIP file that contains the CyberAuditLite script and the tools he runs to audit information from network.
The script takes the tools and compress them into one zip file that you can insert into your internal network.

To run the script run this command:
```powershell
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/contigon/CyberAuditLite/main/MakePackage.ps1')
```

## CyberAuditLite.ps1
The CyberAuditLite tool will run the tools automatically and set a folder with all the outputs of the various tools.


After you extracted the zip created by MakePackage.ps1 on a computer in the internal network, you need to run the following command to be able to run scripts in your computer:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```
Make sure to run this command under administrator permissions

After running this command, you can run the CyberAuditLite.ps1 script by administrator powershell session
