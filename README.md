# CyberAuditLite

This is a 2 phase process:

**Step 1 - MakePackage.ps1**
This Script downloads and excutes automatically so it can download and generate a ZIP file that contains the CyberAuditLite script and the tools
which are needed for running several audit data collection tasks on Active Directory 
(and also optionally can download vulnerabilitiy assesment tools for Databases,OS, networking and more)

Instructions:
1. Open Powershell console as Admin (run as admin)
2. Copy and run the below command to download and run the building phase:
3. Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/contigon/CyberAuditLite/main/MakePackage.ps1')

**Step 2 - CyberAuditLite.ps1**
The CyberAuditLite tool will run the Active Directory collection tools automatically 
and creates a folder with all the outputs of the various tools, which them will be automatically zipped.

Instructions:
1. Extracted the zip file computer on a windows machine connected to the audited domain network
2. Open Powershell console as Admin (run as admin)
3. Run the commands below to start the audit collection phase:
4. Set-ExecutionPolicy -ExecutionPolicy Unrestricted
5. .\CyberAuditLite.ps1
6. You then need to supply Domain Admin credentials in order to run the collection successfully
7. Wait untill script finishes and a zip file created with all data collected

