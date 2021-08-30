#Import-Module $PSScriptRoot\CyberFunctions.psm1
<#
.DESCRIPTION
    If you want to add tools to download, add the name to $ToolsList array, and add a block for it in the switch below
    Dont forget to set $ToolURL to the URL of the tool's download link
#>
enum Tools {
    Goddi
    NTDSAudit
    PingCastle
    Testimo
    CyberAuditLiteFD
    CyberFunctions
    DSInternals    
    putty
    WinSCP
    GoogleChrome
    NotepadPlusPlus
    azscan
    Scuba
    LanTopoLog
}
$FailedToDownloadList = [System.Collections.ArrayList]::new()
$DownloadedSuccessfuly = [System.Collections.ArrayList]::new()
function Get-Tools {

    $global:Root = Get-Folder -EnsureEmpty
    start-Transcript -path $global:Root\MakePackage.Log -Force -append | Out-Null

    (Get-Item $global:Root\MakePackage.Log -Force).Attributes += 'Hidden'
    if (!$global:picks) {
        $maxNum = [Tools].GetEnumNames().Count - 1
        $global:picks = (0..$maxNum)
    }
    Write-Host "Tools for download are: "
    $global:picks.foreach( {
            $name = [Tools].GetEnumName($_)
            Write-Host $name -ForegroundColor Yellow
        })
        
    
    foreach ($ToolNumber in $global:picks) {
        $ToolName = [Tools].GetEnumName($ToolNumber)
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
            CyberAuditLiteFD {
                $ToolURL = "https://raw.githubusercontent.com/maros17/GoGetCyberAuditLite/main/CyberAuditLiteFD.ps1" 
            }
            CyberFunctions {
                $ToolURL = "https://raw.githubusercontent.com/maros17/GoGetCyberAuditLite/main/CyberFunctions.psm1"
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
            Scuba {
                $ToolURL = "https://github.com/contigon/Downloads/raw/master/Scuba-Windows.zip"
                $NeedToExpand = $true
            }
            lantopolog {
                $ToolURL = "https://www.lantopolog.com/files/lantopolog248.zip"
                $NeedToExpand = $true
            }
            
            
            Default { continue }
        }
        $ToolEXEName = Split-Path $ToolURL -Leaf
        if ($ToolEXEName -notmatch '.*\.ps..?$') {
            New-Item  -Path "$global:Root\Tools\$ToolName"  -ItemType "Directory" -Force | out-null
            $ToolLocalPath = "$global:Root\Tools\$ToolName\$ToolEXEName"
        } else {
            $ToolLocalPath = "$global:Root\$ToolEXEName"            
        }
        Write-Host "Downloading $ToolName from $ToolURL" -ForegroundColor Magenta
        if ( dl $ToolURL $ToolLocalPath) {
            $DownloadedSuccessfuly.Add($ToolName)
            if ($NeedToExpand) {
                Write-Host "Expanding $ToolName archive" -ForegroundColor Magenta            
                $ToolDirectory = Split-Path $ToolLocalPath -Parent
                Expand-Archive -Path $ToolLocalPath -DestinationPath $ToolDirectory -Force
                Remove-Item $ToolLocalPath -Force
            }
        } else {
            $FailedToDownloadList.Add($ToolName)
        }
    }
    return ($DownloadedSuccessfuly.Count -gt 0)
}
function Compress-All {
    $ContentToCompress = Get-ChildItem -Path $global:Root -Exclude "*.log" 
    $ContentToCompress | Compress-Archive -DestinationPath $global:Root\CyberAuditLiteFD.zip -Verbose -Force 
    $ContentToCompress | Remove-Item -Force -Recurse
}
function dl($url, $to) {
    $success = $true
    try {
        $wc = New-Object Net.Webclient
        $wc.headers.add('Referer', (strip_filename $url))
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

function ChooseTools {
    [Tools].GetEnumNames() | ForEach-Object {
        "{2}{1,-3} {0}" -f $_, " --", [int]([Tools]::$_)
    }
    $userInput = Read-Host "Please choose with comma seperation"
    if (![string]::IsNullOrEmpty) {
        $userinput = $userInput -replace "\s", ""
        if ($userInput -notmatch '^(\d+,)*\d+$') {
            Write-Error -Category InvalidArgument
        }
        [int[]]$global:picks = $userInput -split ","
        foreach ($p in $global:picks) {
            if (![Tools].GetEnumName($p)) {
                Write-Error -Category ObjectNotFound
            }
        }
    } else { $global:picks = $null }
}

ChooseTools
if (Get-Tools) {
    Compress-All
    Write-Host "`nCongrats, you have a zip file in the directory you selected. Insert the zip file into your network" -ForegroundColor Green
    Write-Host "These files downloaded successfuly" -ForegroundColor Green
    $output = $DownloadedSuccessfuly.ToArray() -join "`n- "
    Write-Host $output -ForegroundColor Green

    if ($FailedToDownloadList.Count -gt 0) {
        Write-Host "But notice that failed to download these tools" -BackgroundColor Green -ForegroundColor Red
        $output = $FailedToDownloadList.ToArray() -join "`n- "
        Write-Host $output -ForegroundColor Red

    }
    
    $null = start-Process -PassThru explorer $global:Root
} else {
    Write-Host "`nAn error accured, couldnt download any file" -BackgroundColor Red -ForegroundColor Black
}


Stop-Transcript | Out-Null