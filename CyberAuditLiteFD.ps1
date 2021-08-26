<#
    .Description
    An automation tool for getting an information of the domain

 .Dependencies
    - Goddi
    - NTDAAudit
    - PingCastle
    - Testimo modules and all its dependent modules
    - CyberFunctions module
    - RSAT
#>

start-Transcript -path $PSScriptRoot\CyberAuditFDPhase.Log -Force -append | Out-Null
Import-Module $PSScriptRoot\CyberFunctions.psm1

function Start-Goddi {
    $help = @"

goddi
-----

goddi (go dump domain info) dumps Active Directory domain information.

Functionality:
- Extract Domain users
- Users in priveleged user groups (DA, EA, FA)
- Users with passwords not set to expire
- User accounts that have been locked or disabled
- Machine accounts with passwords older than 45 days
- Domain Computers
- Domain Controllers
- Sites and Subnets
- SPNs and includes csv flag if domain admin
- Trusted domain relationships
- Domain Groups
- Domain OUs
- Domain Account Policy
- Domain deligation users
- Domain GPOs
- Domain FSMO roles
- LAPS passwords
- GPP passwords. On Windows

In order for this script to succeed you need to have a user with 
Domain Admin permissions.
        
"@
    Write-Host $help
    if ((Get-ChildItem -Filter "goddi-windows-amd64.exe" -Path $PSScriptRoot  -Recurse) ) {
        $goddiEXE = (Get-ChildItem -Filter "goddi-windows-amd64.exe" -Path $PSScriptRoot  -Recurse)[0].FullName
        $goddiDirectory = Split-Path $goddiEXE -Parent
    } else {
        write-Host "If you already have the program, type [Y] to choose its location 
        If you dont have the program, press ENTER to Download it automaticly: " -ForegroundColor Yellow -NoNewline 
        $userInput = Read-Host
        if ($userInput -ieq "y") {
            $goddiDirectory = Get-ToolsFolder -ToolEXEName "goddi-windows-amd64.exe"
            $goddiEXE = "$goddiDirectory\goddi-windows-amd64.exe"
            
        } else {
            $goddiEXE = DownloadTool "goddi-windows-amd64.exe"
            $goddiDirectory = Split-Path $goddiEXE -Parent
        }
    }
    
    $ACQ = ACQ("goddi")
    Write-Host "You are running as user: $env:USERDNSDOMAIN\$env:USERNAME"
    $securePwd = Read-Host "Input a Domain Admin password" -AsSecureString
    $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
    while ([string]::IsNullOrEmpty($Password)) {
        Write-Host "Cannot continue without a password" -ForegroundColor Red
        $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
    }
    if ([string]::IsNullOrEmpty($env:USERDNSDOMAIN)) { 
        $xDNSDOMAIN = Read-Host "Enter the name of the domain full name (etc: domain.local)"
    } else { $xDNSDOMAIN = $env:USERDNSDOMAIN }
    $DC = ($env:LOGONSERVER).TrimStart("\\")
    $cmd = "$goddiEXE -username=`"$env:USERNAME`" -password=`"$Password`" -domain=`"$xDNSDOMAIN`" -dc=`"$DC`" -unsafe"
    Invoke-Expression $cmd
    Move-Item -Path $goddiDirectory\csv\* -Destination $ACQ -Force
}

function Get-NTDS {
    $help = @"
    
NTDS and SYSTEM hive remote aquisition
--------------------------------------

This script will try to connect to $DC Domain controller and create a remote backup of the
ntds.dit database, SYSTEM hive and SYSVOL, and then copies the files to the aquisition folder.

In order for this script to succeed you need to have domain administrative permissions.

Note: This script supports AD running on Windows Servers 2012 and up,
      on windows 2003/2008 we will show the manual instructions. 
        
"@
    Write-Host $help
    $ACQ = ACQ("NTDS")
    $winVer = Invoke-Command -ComputerName $DC -ScriptBlock { (Get-WmiObject -class Win32_OperatingSystem).Caption } -credential $cred
    if ($winVer.contains("2003") -or $winVer.contains("2008")) {
        Write-Host "The domain server is " $winVer -ForegroundColor Red
        $block = @"

Below window 2012 we cant backup the files remotely, 
you will need to do it locally on the Domain Controller
run these steps from elevated CMD:
--------------------------
1. ntdsutil
2. activate instance ntds
3. ifm
4. create sysvol full C:\ntdsdump
5. quit
6. quit
--------------------------
when finished please copy the c:\ntdsdump directory to the Aquisition folder (NTDS)

"@
        Write-Host $block -ForegroundColor Red
    } else {
        $cmd = 'Get-Date -Format "yyyyMMdd-HHmm"'
        $currentTime = Invoke-Expression $cmd
        Write-Host "Please wait untill the backup process is completed" -ForegroundColor Green
        remove-item $env:LOGONSERVER\c$\ntdsdump -Recurse -ErrorAction SilentlyContinue
        winrs -r:$DC ntdsutil "ac i ntds" "ifm" "create sysvol full c:\ntdsdump\$currentTime" q q
        Copy-Item -Path $env:LOGONSERVER\c$\ntdsdump\$currentTime -Destination $ACQ\$currentTime -Recurse -Force
    }

    Start-NTDSAuditTool "$ACQ\$currentTime"
}

function Start-NTDSAuditTool {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $NTDS_ACQ_Path
    )
    $help = @"
    
    hash dumping
    ------------

    Process NTDS/SYSTEM files and export pwdump/ophcrack files using NtdsAudit and
    DSINternals tools.

    NtdsAudit is an application to assist in auditing Active Directory databases,        
    and provides some useful statistics relating to accounts and passwords.

    DSinternals is a Directory Services Internals PowerShell Module and Framework.
    we will use the Get-ADDBAccount function retrieve accounts from an Active Directory database file
    and dump the users password hashes to Ophcrack, HashcatNT, HashcatLM, JohnNT and JohnLM formats.

    Both tools requires the ntds.dit Active Directory database, and optionally the 
    SYSTEM registry hive if dumping password hashes

"@
    write-host $help
    $ACQ = $NTDS_ACQ_Path
    if ((Get-ChildItem -Filter "NTDSAudit.exe" -Path $PSScriptRoot  -Recurse) ) {
        $NTDSAuditEXE = (Get-ChildItem -Filter "NTDSAudit.exe" -Path $PSScriptRoot  -Recurse)[0].FullName
        $NTDSDirectory = Split-Path $NTDSAuditEXE -Parent
    } else {
        write-Host "If you already have the program, type [Y] to choose its location 
        If you dont have the program, press ENTER to Download it automaticly: " -ForegroundColor Yellow -NoNewline 
        $userInput = Read-Host
        if ($userInput -ieq "y") {
            $NTDSDirectory = Get-ToolsFolder -ToolEXEName "NtdsAudit.exe"
            $NTDSAuditEXE = "$NTDSDirectory\NtdsAudit.exe"
            
        } else {
            $NTDSAuditEXE = DownloadTool "NTDSAudit.exe"
            $NTDSDirectory = Split-Path $NTDSAuditEXE -Parent
        }
    }
    # Move all the files from the dump to the main directory
    Get-ChildItem -Path $ACQ -Recurse -File | Move-Item -Destination $ACQ -Force
    $cmd = "$NTDSAuditEXE $ACQ\ntds.dit -s $ACQ\SYSTEM  -p  $ACQ\pwdump.txt -u  $ACQ\user-dump.csv --debug"
    Invoke-Expression $cmd
    Install-DSInternalsModule
    $bk = Get-BootKey -SystemHivePath $ACQ\SYSTEM
    #$fileFormat = @("Ophcrack","HashcatNT","HashcatLM","JohnNT","JohnLM")
    $fileFormat = @("Ophcrack")
    foreach ($f in $fileFormat) {
        Write-Host "[Success] Exporting hashes to $f format" -ForegroundColor Green
        Get-ADDBAccount -All -DBPath $ACQ\ntds.dit -BootKey $bk | Format-Custom -View $f | Out-File $ACQ\hashes-$f.txt -Encoding ASCII
    }
    
    Success "Creating the DomainStatistics.txt report from CyberAuditFDPhase.Log"
    Select-String "Account stats for:" $PSScriptRoot\CyberAuditFDPhase.Log -Context 0, 20 | ForEach-Object { 
        $_.context.PreContext + $_.line + $_.Context.PostContext
    } | Out-File $ACQ\DomainStatistics.txt

}
<#
Function ACQA {
    Param ($dir)
    $ACQdir = ("$AcqBaseFolder\$dir").Replace("//", "/")
    if (Test-Path -Path $ACQdir) {
        Write-Host "[Note] $ACQdir folder already exsits, this will not affect the process" -ForegroundColor Gray
    } else {
        $ACQdir = New-Item -Path $AcqBaseFolder -Name $dir -ItemType "directory" -Force
        write-host "$ACQdir was created successfuly" -ForegroundColor Green
    }
    Return $ACQdir
}
#>
    
function Get-ToolsFolder {
    param (
        # The name of the exe file *with* the ".exe" postfix (or any extension)
        $ToolEXEName
    )    
    write-host "A GUI window will be open to choose a folder" -foregroundcolor Yellow
    $Path = Get-Folder -Description "Choose the folder that contains $ToolEXEName files" -DisableNewFolder -ReturnCancelIfCanceled
    while (($Path -ne "Cancel") -and (-not (Test-Path "$Path\$ToolEXEName"))) {
        Write-Host "Cannot find the file `"$ToolEXEName`"" -ForegroundColor Red 
        $Path = Get-Folder -Description "Choose the folder that contains $ToolEXEName files" -DisableNewFolder -ReturnCancelIfCanceled
    }
    if ($Path -eq "Cancel") { 
        Write-Error -Message "File selection canceled, cannot continue!" -ErrorAction Stop
    }
    return $Path     
}
# Getting to DSInternals module from its zip, extract it directly to the place where local module are
# Then imports the module for the current session
function Install-DSInternalsModule {
    
    if (Get-ChildItem -path "$PSScriptRoot" -Filter "DSInternals.zip" -File -Recurse) {
        $ZIPFilePath = (Get-ChildItem -path "$PSScriptRoot" -Filter "DSInternals.zip" -File -Recurse)[0].FullName
    } else {
        Write-Host "[Failed] Cannot find DSInternals.zip, please select its zip file" -ForegroundColor Red
        Write-Host "You can select the file location, or Download it automaticly" -ForegroundColor Red 
        $userInput = Read-Host "Press ENTER to download it automaticly, or type [L] to locate it locally"
        if ($userInput -eq "L") {                
            $ZIPFilePath = Get-FileName -Extensions "zip"
        } else {
            if (!(Get-PackageProvider -Name nuget)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }
            if (!(Get-Module -Name PowerShellGet)) {
                Install-Module -Name PowerShellGet -Force
            }
            Install-Module -Name DSInternals
            return
        }            
    }
    $ModuleDestination = ($env:PSModulePath -split ";" | Select-String "$env:USERPROFILE" -SimpleMatch).ToString()
    Unblock-File -Path "$ZIPFilePath"
    Expand-Archive -Path "$ZIPFilePath" -DestinationPath "$ModuleDestination\" -Force -Verbose
    Import-Module DSInternals -Verbose
}


function Start-PingCastle {
    $help = @"

    PIngCastle
    ----------
    
    Active Directory Security Maturity Self-Assessment, based on CMMI 
    (Carnegie Mellon university 5 maturity steps) where each step has 
    been adapted to the specificity of Active Directory. 

    In order for this script to succeed you need to have a user with 
    Domain Admin permissions.
            
"@
    Write-Host $help
    $ACQ = ACQ("PingCastle")
    if ((Get-ChildItem -Filter "pingcastle.exe" -Path $PSScriptRoot  -Recurse) ) {
        $PingCastleFolder = (Get-ChildItem -Filter "pingcastle.exe" -Path $PSScriptRoot  -Recurse)[0].DirectoryName
    } else {
        write-Host "If you already have the program, type [Y] to choose its location 
If you dont have the program, press ENTER to Download it automaticly: " -ForegroundColor Yellow -NoNewline 
        $userInput = Read-Host
        if ($userInput -ieq "y") {
            $PingCastleFolder = Get-ToolsFolder "Pingcastle.exe"
        } else {
            $PingCastleZIP = DownloadTool "PingCastle"
            $PingCastleZIPParent = Split-Path $PingCastleZIP -Parent
            Expand-Archive -Path $PingCastleZIP -DestinationPath $PingCastleZIPParent -Force
            $PingCastleFolder = $PingCastleZIPParent
        }
        
    }

    Invoke-Command -ScriptBlock {
        push-Location $ACQ
        $cmd = "robocopy $PingCastleFolder $ACQ /e /njh"
        Invoke-Expression $cmd

        Start-Job -Name "full" -ScriptBlock { Push-Location $using:ACQ; cmd /c start .\PingCastle  --server * --no-enum-limit --carto --healthcheck; Pop-Location }
        Wait-Job -Name "full"
        Start-Job -Name "conso" -ScriptBlock { Push-Location $using:ACQ; cmd /c start .\PingCastle --hc-conso; Pop-Location }
        Wait-Job -Name "conso"
        $checks = @("antivirus", "corruptADDatabase", "laps_bitlocker", "localadmin", "nullsession", "nullsession-trust", "share", "smb", "spooler", "startup")
        foreach ($check in $checks) {
            Start-Job -Name "scan" -ScriptBlock { Push-Location $using:ACQ; cmd /c start .\PingCastle --scanner $check; Pop-Location }
            Wait-Job -Name "scan"       
        }        
        Pop-Location
    }
    
 
}
function Start-Testimo {
    $help = @"

    Testimo
    -------
    
    PowerShell module for running health checks for Active Directory 
    (and later on any other server type) against a bunch of different tests.

    Tests are based on:
    - Active Directory CheckList
    - AD Health & Checkup
    - Best Practices

    In order for this script to succeed you need to have a user with 
    Domain Admin permissions.
            
"@
    Write-Host $help 
    Write-Host $help 
    Write-Host $help 
    Install-TestimoModules
  
    $ACQ = ACQ("Testimo")
    if (checkRsat) {
        import-module activedirectory ; Get-ADDomainController -Filter * | Select-Object Name, ipv4Address, OperatingSystem, site | Sort-Object -Property Name
        Invoke-Testimo  -ExcludeSources DCDiagnostics -ReportPath $ACQ\Testimo.html
    }
}
function Install-TestimoModules {
    if (Get-ChildItem -Filter "TestimoAndDependecies.zip" -Recurse) {
        $ModulesZip = (Get-ChildItem -Filter "TestimoAndDependecies.zip" -Recurse)[0].FullName
    } else {
        Write-Host "[Failed] Cannot find DSInternals.zip, please select its zip file" -ForegroundColor Red
        Write-Host "You can select the file location, or Download it automaticly" -ForegroundColor Red 
        $userInput = Read-Host "Press ENTER to download it automaticly, or type [L] to locate it localy"
        if ($userInput -eq "L") {       
            write-host "A windows will open to select a file, Please select the ZIP file contains Testimo-Modules.zip"
            Read-Host "Press ENTER to continue"
            $ModulesZip = get-filename -Extensions "zip"
        } else {
            if (!(Get-PackageProvider -Name nuget)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }
            if (!(Get-Module -Name PowerShellGet)) {
                Install-Module -Name PowerShellGet -Force
            }
            Install-Module -Name Testimo -force
            return
        }
    }
    $ModuleDestination = ($env:PSModulePath -split ";" | Select-String "$env:USERPROFILE" -SimpleMatch).ToString()
    Expand-Archive -Path $ModulesZip -DestinationPath $ModuleDestination -Force

    $Modules = @(
        "PSWriteHTML"
        "PSEventViewer"
        "Connectimo"
        "PSWriteColor"
        "GPOZaurr"
        "ADEssentials"
        "PSWinDocumentation.DNS"
        "PSSharedGoods"
        "testimo"
    )
    foreach ($_ in $Modules) {
        Import-Module $_  -Force -Verbose
    }
}
function DownloadTool {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ToolName
    )
    switch ($ToolName) {
        "Goddi" { $ToolURL = "https://github.com/NetSPI/goddi/releases/download/v1.2/goddi-windows-amd64.exe" }
        "NTDSAudit" { $ToolURL = "https://github.com/Dionach/NtdsAudit/releases/download/v2.0.7/NtdsAudit.exe" }
        "PingCastle" { $ToolURL = "https://github.com/vletoux/pingcastle/releases/download/2.10.0.0/PingCastle_2.10.0.0.zip" }
        "Testimo" { $ToolURL = "https://github.com/maros17/Downloads/raw/main/TestimoAndDependecies.zip" }
        Default {}
    }    
    $ToolEXEName = fname $ToolURL
    New-Item  -Path "$PSScriptRoot\$ToolName"  -ItemType "Directory" -Force | out-null
    dl $ToolURL "$PSScriptRoot\$ToolName\$ToolEXEName"
    return "$PSScriptRoot\$ToolName\$ToolEXEName"    
}
function Connect-Domain {
    write-Host "Your computer is not connected to any domain. Do you want to register to a domain?" -ForegroundColor Yellow 
    do {   
        write-Host "To register the computer enter the name of the domain. Leave empty to exit" -ForegroundColor Yellow 
        write-Host "Please make sure you enter the full name of the domain, i.e. `"Domain.Local`": " -ForegroundColor Yellow -NoNewline
        $domain = Read-Host
        if ([string]::IsNullOrEmpty($domain)) { return }
        $username = read-host -Prompt "Enter an admin user name which have enough permissions"
        $password = Read-Host -Prompt "Enter password for $user" -AsSecureString
        $username = $domain + "\" + $username
        $credential = New-Object System.Management.Automation.PSCredential($username, $password)
        if (-not((Add-Computer -DomainName $domain -Credential $credential -PassThru -Force -Verbose).HasSucceeded)) {
            Write-Host "Failed to register the computer to the domain `"$domain`" " -ForegroundColor Red
            Write-Host "Check the properties and try again" -ForegroundColor Yellow
            Write-Host "If you want to try again, prass [A]: " -ForegroundColor Yellow -NoNewline
            $userInput = Read-Host
            if ($userInput -eq "A") { $Continue = $true }
            else { return }
        } else {
            $Continue = $false
        }
    }while ($Continue)
    Write-Host "We have to restart your computer now to apply the changes and let you to login to windows with domain-admin user" -ForegroundColor Yellow
    Write-Host "Do you want to restart your computer now or do it manually?" -ForegroundColor Yellow
    Write-Host "To restart your computer right now, enter `"restart`": " -ForegroundColor Yellow -NoNewline
    $userInput = Read-Host 
    if ($userInput -eq "restart") { Restart-Computer -Force }
    else { return }
    
}
function Test-DomainAdmin {
    # 1-liner to check members of the "Domain Admins" Group
    try {
        $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | ForEach-Object { Get-ADUser -Identity $_.distinguishedName }  | Where-Object { $_.Enabled -eq $True }  | Select-Object  -ExpandProperty SamAccountName
        if ($DomainAdmins.Contains($env:USERNAME)) {
            Write-Host "You have Domain-Admin permissions" -ForegroundColor Green
            return $true
        } else {
            Write-Host "To run the tools you need to run script by a Domain-Admin user"
            return $false
        }    
    } catch { return $false }
}
# Check if RSAT is installed
if (CheckRSAT) { Import-Module ActiveDirectory }
else { return}
# Check if the machine is in a domain. If not, suggests to connect to a domain
if (-not (CheckMachineRole)) { Connect-Domain }
# Ensure current user have Domain-Admin privileges
if (-not (Test-DomainAdmin)) { 
    Write-Host "To run the tools you need to run script by a Domain-Admin user"    
    return 
}

$DC = ($env:LOGONSERVER).TrimStart("\\")

Start-Goddi
Get-NTDS
Start-PingCastle
Start-Testimo
read-host "Press ENTER to continue"
$ACQ = ACQBaseFolder
$null = start-Process -PassThru explorer "$ACQ"
stop-Transcript | out-null
