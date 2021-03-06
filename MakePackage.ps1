<#
.DESCRIPTION
    
.NOTES
    If you want to add tools to download, add the name to [GUITools]/[CLITools] enum, and add a block for it in the switch below
    Dont forget to set $ToolURL to the URL of the tool's download link
#>


function ShowINCD() {
    $incd = @"                                                                        
    

   _____               _______   _       _____  _______  ______ 
  / ____|       /\    |__   __| | |     |_   _||__   __||  ____|
 | |           /  \      | |    | |       | |     | |   | |__   
 | |          / /\ \     | |    | |       | |     | |   |  __|  
 | |____  _  / ____ \  _ | |    | |____  _| |_    | |   | |____ 
  \_____|(_)/_/    \_\(_)|_|    |______||_____|   |_|   |______|

  Cyber Audit Tool (Lite Edition) 
  INCD - Israel Cyber Directorate
  Version: 1.1 October 2021                                                                      
                                                                
"@
    Write-Host $incd -ForegroundColor Green
}

CLS
ShowINCD

enum CLITools {
    Goddi = 1
    NTDSAudit
    PingCastle
    Testimo
    CyberAuditLite
    CyberFunctions
    DSInternals    
}
enum GUITools{
    putty = 1
    WinSCP
    NotepadPlusPlus
    azscan
    Scuba
    LanTopoLog
    EverythingSearch
    Skybox_Appliacne
    Skybox_Guide
    Skybox_Windows
    Nessus
    Runecast
}
$MaxIndexOfSmallTools = [int]([GUITools]::EverythingSearch)
start-Transcript -path "$env:USERPROFILE\Documents\CyberAudit\MakePackage.Log" -Force -append | Out-Null

# Sets a list for the tools downloaded successfuly and for tools that failed to download
# It's only for showing to user the status of the download at the end of the script
$FailedToDownloadList = [System.Collections.ArrayList]::new()
$DownloadedSuccessfuly = [System.Collections.ArrayList]::new()
function Get-Tools {

<#
.SYNOPSIS
Check the tools in [CLITools] enum and the selected tools in $picks of [GUITools] enum, and download them with dl function

.NOTES
General notes
#>
    $global:Root = Get-Folder -EnsureEmpty

    Write-Host "Tools that will be downloaded are:" -ForegroundColor Yellow
    foreach ($ToolName in [CLITools].GetEnumNames()) {
        Write-Host "- $ToolName" -ForegroundColor Yellow
    }
    $global:picks.foreach( {
            $name = [GUITools].GetEnumName($_)
            Write-Host "- $name" -ForegroundColor Yellow
        })

    Write-Host "Start downloading tools..." -ForegroundColor Magenta
    # Download CLI Tools
    foreach ($ToolName in [CLITools].GetEnumNames()) {
        DownloadTool $ToolName
    }
    # Download the optional tools chosen by user
    foreach ($ToolNumber in $global:picks) {
        $ToolName = [GUITools].GetEnumName($ToolNumber)
        DownloadTool $ToolName
    }
    return ($DownloadedSuccessfuly.Count -gt 0)
}
#Get a tool name, set a directory for it and download it
function DownloadTool {
    param (
        [Parameter(Mandatory = $true)]        
        $ToolName
    )

    $NeedExpansion = $false
    switch ($ToolName) {
        Goddi {
            $ToolURL = "https://github.com/NetSPI/goddi/releases/download/v1.2/goddi-windows-amd64.exe"
        }
        NTDSAudit {
            $ToolURL = "https://github.com/Dionach/NtdsAudit/releases/download/v2.0.7/NtdsAudit.exe" 
        }
        PingCastle {
            $ToolURL = "https://github.com/vletoux/pingcastle/releases/download/2.10.0.0/PingCastle_2.10.0.0.zip" 
            $NeedExpansion = $true
        }
        Testimo {
            $ToolURL = "https://github.com/contigon/Downloads/raw/master/TestimoAndDependecies.zip"
        }
        CyberAuditLite {
            $ToolURL = "https://raw.githubusercontent.com/contigon/CyberAuditLite/main/CyberAuditLite.ps1" 
        }
        CyberFunctions {
            $ToolURL = "https://raw.githubusercontent.com/contigon/CyberAuditLite/main/CyberFunctions.psm1"
        }
        DSInternals {
            $ToolURL = "https://github.com/MichaelGrafnetter/DSInternals/releases/download/v4.4.1/DSInternals_v4.4.1.zip"
        }
        Putty {
            $ToolURL = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"
        }
        azscan {
            $ToolURL = "https://cxlsecure.com/azscan3-install.exe"
        }
        WinSCP {
            $ToolURL = "https://winscp.net/download/WinSCP-5.17.9-Portable.zip"
        }
        NotepadPlusPlus {
            $ToolURL = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8/npp.8.0.portable.zip"
            $NeedExpansion = $true
        }
        Scuba {
            $ToolURL = "https://github.com/contigon/Downloads/raw/master/Scuba-Windows.zip"
        }
        lantopolog {
            $ToolURL = "https://www.lantopolog.com/files/lantopolog248.zip"
            $NeedExpansion = $true
        }
        EverythingSearch {
            $ToolURL = "https://www.voidtools.com/Everything-1.4.1.1009.x64.zip"
            $NeedExpansion = $true
        }
        Skybox_Appliacne {
            $ToolURL = 'https://downloads.skyboxsecurity.com/files/iso/Skybox_11.4.122-7.1.333/ISO/Skybox_11.4.122-7.1.333.iso'  
        }
        Skybox_Windows {
            $ToolURL = 'https://downloads.skyboxsecurity.com/files/Installers/Skybox_View/11.4/11.4.100/SkyboxManager-11.4.125-274.exe'
        }
        Skybox_Guide {
            $ToolURL = 'https://downloads.skyboxsecurity.com/files/iso/latestDocs/Skybox%20Virtual%20Appliance%20Quick%20Start%20Guide.pdf'
        }
        Nessus {
            $ToolURL = 'https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/13315/download?i_agree_to_tenable_license_agreement=true'
        }
        Runecast {
            $ToolURL = 'https://updates.runecast.com/ova/RunecastAnalyzer.ova'
        }
        Default { continue }
    }
    # Set the destination directory for the tool
    # Take the script to the main directory, and any other tool to a dedicated
    $ToolEXEName = Split-Path $ToolURL -Leaf
    # Put all skybox files in one directory
    if ($ToolName -match '^skybox.*') {
        New-Item  -Path "$global:Root\Tools\Skybox" -ItemType "Directory" -Force | out-null
        $ToolLocalPath = "$global:Root\Tools\Skybox\$ToolEXEName"
    } elseif ($ToolEXEName -notmatch '.*\.ps..?$') {
        New-Item  -Path "$global:Root\Tools\$ToolName"  -ItemType "Directory" -Force | out-null
        $ToolLocalPath = "$global:Root\Tools\$ToolName\$ToolEXEName"
    } else {
        $ToolLocalPath = "$global:Root\$ToolEXEName"            
    }
    
    Write-Host "Downloading $ToolName from $ToolURL" -ForegroundColor Magenta
    # Nessus download needs a special care because its a GET request, not just a file to
    if ($ToolName -eq "Nessus") {
        try {
            $ToolLocalPath = "$global:Root\Tools\$ToolName\Nessus.msi"
            $ProgressPreferenceTemp = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $ToolURL -OutFile $ToolLocalPath
            $ProgressPreference = $ProgressPreferenceTemp
            $DownloadedSuccessfuly.Add($ToolName) | Out-Null
        } catch {
            Write-Host "ERROR: Couldnt download nessus" -ForegroundColor Red
             $FailedToDownloadList.Add($ToolName) 
            }
        return
    }

    if ( dl $ToolURL $ToolLocalPath) {
        $DownloadedSuccessfuly.Add($ToolName) | Out-Null
        # If tool is a zip file, expands the zip and remove the zip ater the expansion
        if ($NeedExpansion) {
            Write-Host "Expanding $ToolName archive" -ForegroundColor Magenta            
            $ToolDirectory = Split-Path $ToolLocalPath -Parent
            Expand-Archive -Path $ToolLocalPath -DestinationPath $ToolDirectory -Force
            if ($?) { Remove-Item $ToolLocalPath -Force }
        }
    } else { $FailedToDownloadList.Add($ToolName) | Out-Null }    
}
# Compress all the files that downloaded and delete the origin after the compression
function Compress-All {
    $ContentToCompress = Get-ChildItem -Path $global:Root -Exclude "*.log" 
    $ContentToCompress | Compress-Archive -DestinationPath $global:Root\CyberAuditLite.zip -Verbose -Force 
    $ContentToCompress | Remove-Item -Force -Recurse
}
function dl($url, $to) {
    $success = $true
    try {
        $wc = New-Object Net.Webclient
        $wc.headers.Add('Referer', (strip_filename $url))
        $wc.Headers.Add('User-Agent', (Get-UserAgent))
        $wc.downloadFile($url, $to)
    } catch {
        Write-Host "ERROR: download from $url failed" -ForegroundColor Red
        $success = $false
    }
    return $success
}
function Get-UserAgent() {
    return "CyberAuditTool/1.0 (+http://cyberaudittool.c1.biz/) PowerShell/$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) (Windows NT $([System.Environment]::OSVersion.Version.Major).$([System.Environment]::OSVersion.Version.Minor); $(if($env:PROCESSOR_ARCHITECTURE -eq 'AMD64'){'Win64; x64; '})$(if($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64'){'WOW64; '})$PSEdition)"
}

function fname($path) { split-path $path -leaf }
function strip_filename($path) { $path -replace [regex]::escape((fname $path)) }
# Show a window to select a folder
Function Get-Folder {
    param (
        $initialDirectory,
        [switch]
        $EnsureEmpty
    )
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowserDialog.RootFolder = 'MyComputer'
    $FolderBrowserDialog.Description = "Please select an empty folder"
    if ($initialDirectory) { $FolderBrowserDialog.SelectedPath = $initialDirectory }
    $Topmost = New-Object System.Windows.Forms.Form
    $Topmost.TopMost = $True
    $Topmost.MinimizeBox = $True
    if ( $FolderBrowserDialog.ShowDialog($Topmost) -eq "Cancel")
    { Write-Error "ERROR: Cannot continue without selecting an empty folder" -ErrorAction Stop }
    while (($EnsureEmpty) -and (Get-ChildItem $FolderBrowserDialog.SelectedPath -Force -Recurse)) {
        Write-Host "ERROR: Folder must be empty!" -ForegroundColor Red
        if ( $FolderBrowserDialog.ShowDialog($Topmost) -eq "Cancel")
        { Write-Error "ERROR: Cannot continue without selecting an empty folder" -ErrorAction Stop }
    }
    return $FolderBrowserDialog.SelectedPath
}

# Show a menu that details the tools that will be downloaded, and offer additional tools to download
function Select-Tools {
    # Show to user the tools that will be downloaded
    Write-host "The script will download the tools needed for the audit and compress them as a ZIP file" -ForegroundColor Yellow
    Write-Host ""
    Write-host "CLI Tools for auditing Active Directory:" -ForegroundColor Yellow
    # Show the list of the CLI tools
    [CLITools].GetEnumNames().ForEach( { Write-Host "- $_" -ForegroundColor Yellow })
    Write-Host ""
    Write-host "In addition, you can choose to download these other auditing software and utilities:" -ForegroundColor Yellow
    # Show the list of the optional GUI tools
    [GUITools].GetEnumNames() | ForEach-Object {
        $output = "{2,-3}{1,-2} {0}" -f $_, "--", [int]([GUITools]::$_)
        if (([int]([GUITools]::$_)) -gt $MaxIndexOfSmallTools) { write-host $output -ForegroundColor DarkYellow }
        else { write-host $output -ForegroundColor Yellow }
    }
    
    Write-Host ""
    write-host "Press [Enter] to download only CLI audit Tools" -ForegroundColor Green
    write-host "Press [A] to download CLI And More auditing tools" -ForegroundColor Green
    Write-Host "Press [S] to also download Skybox, nessus and runecast (this can take some time...)" -ForegroundColor Yellow
    write-host "NOTE: Optinally download CLI tools and any optional tools by separating them by a comma (eg. 1,3,6)" -ForegroundColor Yellow
    $userInput = Read-Host
    
    # Checks userInput is not empty
    if (![string]::IsNullOrEmpty($userInput)) {
        # Remove White spaces
        $userinput = $userInput -replace "\s", ""
        if ($userInput -eq "A") { [int[]]$global:picks = @(1..$MaxIndexOfSmallTools); return }
        if ($userInput -eq "S") { [int[]]$global:picks = @(1..[GUITools].GetEnumNames().Count); return }
        # Make sure that user input is only numbers seperated by comma
        elseif ($userInput -notmatch '^(\d+,)*\d+$') {
            Write-Error -Category InvalidArgument
        }
        # Takes user input string, puts it into an array, and clean duplicates
        [int[]]$global:picks = $userInput -split "," | Select-Object -Unique
        # Make sure that all the numbers that user chose is valid options in the enum
        foreach ($p in $global:picks) {
            if (![GUITools].GetEnumName($p)) {
                Write-Error "Invalid number(s)" -Category ObjectNotFound -ErrorAction Stop
            }
        }
    } else { $global:picks = $null }
}
Select-Tools
if (Get-Tools) {
    Compress-All
    Write-Host ""
    Write-Host "[Finished] Zip file containing all tools is ready" -ForegroundColor Green
    Write-Host "These files downloaded successfuly:" -ForegroundColor Green    
    $DownloadedSuccessfuly.ForEach( { Write-Host "- $_" -ForegroundColor Green })
    
    if ($FailedToDownloadList.Count -gt 0) {
        Write-Host "But notice that failed to download these tools" -BackgroundColor Green -ForegroundColor Red
        $FailedToDownloadList.ForEach( { Write-Host "- $_" -ForegroundColor Red })
    }
    
    # Show the zip file in Explorer
    $null = start-Process -PassThru explorer $global:Root
        } else {
            Write-Host "An error accured, couldnt download any file" -BackgroundColor Red -ForegroundColor Black
        }

    Write-Host ""

    Write-Host "Isstructions:" -ForegroundColor Green
    Write-Host "1. Extract the zip file on a windows machine connected to the domain" -ForegroundColor Green
    Write-Host "2. open powershell console as Admin" -ForegroundColor Green
    Write-Host "3. run the script CyberAuditLite.ps1" -ForegroundColor Green
    Write-Host "4. wait untill script finishes runnig (this can take some time)" -ForegroundColor Green
    Write-Host "5. All data collected will be compressed to a zip file" -ForegroundColor Green

# Make the transcript folder hidden
(Get-Item "$env:USERPROFILE\Documents\CyberAudit" -Force).Attributes += 'Hidden'
Stop-Transcript | Out-Null