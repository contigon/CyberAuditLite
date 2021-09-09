<#
.DESCRIPTION
    
.NOTES
    If you want to add tools to download, add the name to [GUITools]/[CLITools] enum, and add a block for it in the switch below
    Dont forget to set $ToolURL to the URL of the tool's download link
#>

enum CLITools {
    Goddi = 1
    NTDSAudit
    PingCastle
    Testimo
    CyberGatito
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
}
start-Transcript -path "$env:USERPROFILE\Documents\CyberAudit\MakePackage.Log" -Force -append | Out-Null

# Sets a list for the tools downloaded successful and for the tool failed to download
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

    Write-Host "`n`nTools that will be downloaded are: " -ForegroundColor Yellow
    foreach ($ToolName in [CLITools].GetEnumNames()) {
        Write-Host "- $ToolName" -ForegroundColor Yellow
    }
    $global:picks.foreach( {
            $name = [GUITools].GetEnumName($_)
            Write-Host "- $name" -ForegroundColor Yellow
        })
        
    # Download CLI Tools
    foreach ($ToolName in [CLITools].GetEnumNames()) {
        Receive-Tool $ToolName
    }       
    # Download the optional tools chosen by user
    foreach ($ToolNumber in $global:picks) {
        $ToolName = [GUITools].GetEnumName($ToolNumber)
        Receive-Tool $ToolName
    }
    return ($DownloadedSuccessfuly.Count -gt 0)
}
#Get a tool name, set a directory for it and download it
function Receive-Tool {
    param (
        [Parameter(Mandatory = $true)]        
        $ToolName
    )

    $NeedToExpand = $false
    switch ($ToolName) {
        Goddi {
            $ToolURL = "https://github.com/NetSPI/goddi/releases/download/v1.2/goddi-windows-amd64.exe"
        }
        NTDSAudit {
            $ToolURL = "https://github.com/Dionach/NtdsAudit/releases/download/v2.0.7/NtdsAudit.exe" 
        }
        PingCastle {
            $ToolURL = "https://github.com/vletoux/pingcastle/releases/download/2.10.0.0/PingCastle_2.10.0.0.zip" 
            $NeedToExpand = $true
        }
        Testimo {
            $ToolURL = "https://github.com/maros17/Downloads/raw/main/TestimoAndDependecies.zip"
        }
        CyberGatito {
            $ToolURL = "https://raw.githubusercontent.com/maros17/GoGetCyberGatito/main/CyberGatito.ps1" 
        }
        CyberFunctions {
            $ToolURL = "https://raw.githubusercontent.com/maros17/GoGetCyberGatito/main/CyberFunctions.psm1"
        }
        DSInternals {
            $ToolURL = "https://github.com/maros17/Downloads/raw/main/DSInternals.zip"
        }
        Putty {
            $ToolURL = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"
        }
        azscan {
            $ToolURL = "https://cxlsecure.com/azscan3-install.exe"
        }
        WinSCP {
            $ToolURL = "https://winscp.net/download/WinSCP-5.17.9-Portable.zip"
            $NeedToExpand = $true
        }
        NotepadPlusPlus {
            $ToolURL = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8/npp.8.0.portable.zip"
            $NeedToExpand = $true
        }
        Scuba {
            $ToolURL = "https://github.com/contigon/Downloads/raw/master/Scuba-Windows.zip"
            $NeedToExpand = $true
        }
        lantopolog {
            $ToolURL = "https://www.lantopolog.com/files/lantopolog248.zip"
            $NeedToExpand = $true
        }
        EverythingSearch {
            $ToolURL = "https://www.voidtools.com/Everything-1.4.1.1009.x64.zip"
            $NeedToExpand = $true
        }
        Default { continue }
    }
    # Set the destination directory for the tool
    # Take the script to the main directory, and any other tool to a dedicated
    $ToolEXEName = Split-Path $ToolURL -Leaf
    if ($ToolEXEName -notmatch '.*\.ps..?$') {
        New-Item  -Path "$global:Root\Tools\$ToolName"  -ItemType "Directory" -Force | out-null
        $ToolLocalPath = "$global:Root\Tools\$ToolName\$ToolEXEName"
    } else {
        $ToolLocalPath = "$global:Root\$ToolEXEName"            
    }

    Write-Host "Downloading $ToolName from $ToolURL" -ForegroundColor Magenta
    if ( dl $ToolURL $ToolLocalPath) {
        $DownloadedSuccessfuly.Add($ToolName) | Out-Null
        # If tool is a zip file, expands the zip and remove the zip ater the expansion
        if ($NeedToExpand) {
            Write-Host "Expanding $ToolName archive" -ForegroundColor Magenta            
            $ToolDirectory = Split-Path $ToolLocalPath -Parent
            Expand-Archive -Path $ToolLocalPath -DestinationPath $ToolDirectory -Force
            Remove-Item $ToolLocalPath -Force
        }
    } else {
        $FailedToDownloadList.Add($ToolName) | Out-Null
    }    
}
# Compress all the files that downloaded and delete the origin after the compression
function Compress-All {
    $ContentToCompress = Get-ChildItem -Path $global:Root -Exclude "*.log" 
    $ContentToCompress | Compress-Archive -DestinationPath $global:Root\CyberGatito.zip -Verbose -Force 
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
        Write-Host "ERROR: Couldnt download from $url" -ForegroundColor Red
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
    { Write-Error "ERROR: Cannot continue without a folder" -ErrorAction Stop }
    while (($EnsureEmpty) -and (Get-ChildItem $FolderBrowserDialog.SelectedPath -Force -Recurse)) {
        Write-Host "ERROR: Folder must be empty!" -ForegroundColor Red
        if ( $FolderBrowserDialog.ShowDialog($Topmost) -eq "Cancel")
        { Write-Error "ERROR: Cannot continue without a folder" -ErrorAction Stop }
    }
    return $FolderBrowserDialog.SelectedPath
}

# Show a menu that details the tools that will be downloaded, and offer additional tools to download
function Select-Tools {
    # Show to user the tools that will be downloaded
    Write-host "`nThe script will download the next tools and compress them into a ZIP file:`n" -ForegroundColor Yellow
    # Show the list of the CLI tools
    [CLITools].GetEnumNames().ForEach( { Write-Host "- $_" -ForegroundColor Yellow })
    Write-host "`nIn addition, you can choose to download these tools:`n" -ForegroundColor Yellow
    # Show the list of the optional GUI tools
    [GUITools].GetEnumNames() | ForEach-Object {
        $output = "{2,-3}{1,-2} {0}" -f $_, "--", [int]([GUITools]::$_)
        write-host $output -ForegroundColor Yellow
    }
    write-host "`nPress [Enter] to download only CLI audit Tools, or [ALL] to download all tools" -ForegroundColor Yellow
    write-host "Alternativly, you can enter specific numbers of tools you want to download (make sure you separate them by a comma)" -ForegroundColor Yellow
    $userInput = Read-Host
    
    # Checks userInput is not empty
    if (![string]::IsNullOrEmpty($userInput)) {
        # Remove White spaces
        $userinput = $userInput -replace "\s", ""
        # Enter all CLI numbers
        if ($userInput -eq "ALL") { [int[]]$global:picks = @(1..[GUITools].GetEnumNames().Count); return }
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
    Write-Host "`nCongrats, you have a zip file in the directory you selected. Insert the zip file into your network" -ForegroundColor Green
    Write-Host "These files downloaded successfuly:" -ForegroundColor Green    
    $DownloadedSuccessfuly.ForEach( { Write-Host "- $_" -ForegroundColor Green })
    
    if ($FailedToDownloadList.Count -gt 0) {
        Write-Host "But notice that failed to download these tools" -BackgroundColor Green -ForegroundColor Red
        $FailedToDownloadList.ForEach( { Write-Host "- $_" -ForegroundColor Red })
    }
    
    # Show the zip file in Explorer
    $null = start-Process -PassThru explorer $global:Root
} else {
    Write-Host "`nAn error accured, couldnt download any file" -BackgroundColor Red -ForegroundColor Black
}

# Make the transcript folder hidden
(Get-Item "$env:USERPROFILE\Documents\CyberAudit" -Force).Attributes += 'Hidden'
Stop-Transcript | Out-Null