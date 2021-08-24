#Import-Module $PSScriptRoot\CyberFunctions.psm1
<#
.DESCRIPTION
    If you want to add tools to download, add the name to $ToolsList array, and add a block for it in the switch below
    Dont forget to set $ToolURL to the URL of the tool's download link
#>
function Get-Tools {
    $global:Root = Get-Folder -EnsureEmpty

    start-Transcript -path $Root\MakePackage.Log -Force -append | Out-Null
    (Get-Item $Root\MakePackage.Log -Force).Attributes += 'Hidden'
    $ToolsList = @("Goddi", "NTDSAudit", "PingCastle", "Testimo", "CyberAuditLiteFD", "CyberFunctions", "DSInternals")
    foreach ($ToolName in $ToolsList) {
        $NeedToExpand = $false
        switch ($ToolName) {
            "Goddi" {
                $ToolURL = "https://github.com/NetSPI/goddi/releases/download/v1.2/goddi-windows-amd64.exe"
            }
            "NTDSAudit" {
                $ToolURL = "https://github.com/Dionach/NtdsAudit/releases/download/v2.0.7/NtdsAudit.exe" 
            }
            "PingCastle" {
                $ToolURL = "https://github.com/vletoux/pingcastle/releases/download/2.10.0.0/PingCastle_2.10.0.0.zip" 
                $NeedToExpand = $true
            }
            "Testimo" {
                $ToolURL = "https://github.com/maros17/Downloads/raw/main/TestimoAndDependecies.zip"
            }
            "CyberAuditLiteFD" {
                $ToolURL = "https://raw.githubusercontent.com/maros17/GoGetCyberAuditLite/main/CyberAuditLiteFD.ps1" 
            }
            "CyberFunctions" {
                $ToolURL = "https://raw.githubusercontent.com/maros17/GoGetCyberAuditLite/main/CyberFunctions.psm1"
            }
            "DSInternals" {
                $ToolURL = "https://github.com/maros17/Downloads/raw/main/DSInternals.zip"
            }
            Default {}
        }
        $ToolEXEName = Split-Path $ToolURL -Leaf
        if ($ToolEXEName -notmatch ".*.ps") {
            New-Item  -Path "$Root\$ToolName"  -ItemType "Directory" -Force | out-null
            $ToolLocalPath = "$Root\$ToolName\$ToolEXEName"
        } else {
            $ToolLocalPath = "$Root\$ToolEXEName"            
        }
        Write-Host "Downloading $ToolName from $ToolLocalPath" -ForegroundColor Magenta
        if ( dl $ToolURL $ToolLocalPath) {
            # This variable's propose is to indicate that at least on tool downloaded successfuly, and there are tools to compress
            $HadSuccesses = $true
            if ($NeedToExpand) {
                Write-Host "Expanding $ToolName archive" -ForegroundColor Magenta            
                $ToolDirectory = Split-Path $ToolLocalPath -Parent
                Expand-Archive -Path $ToolLocalPath -DestinationPath $ToolDirectory -Force
                Remove-Item $ToolLocalPath
            }
        } else {
            # This variable assigment doesnt change any action of the script, its only notify to user that
            # not all the tools were downloaded successfuly
            $Global:HadFailures = $true
        }
    }
    return $HadSuccesses
}
function Compress-All {
    $ContentToCompress = Get-ChildItem -Path $Root -Exclude "*.log" 
    $ContentToCompress | Compress-Archive -DestinationPath $Root\CyberAuditLiteFD.zip -Verbose -Force 
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

function CheckFolderEmptiness {
    param (
        $FolderPath
    )

    
}
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

if (Get-Tools) {
    Compress-All
    Write-Host "`nCongrats, you have a zip file in the directory you selected. Insert the zip file into your network" -BackgroundColor Green -ForegroundColor Black
    if ($HadFailures) {
        Write-Host "But notice that failed to download some tools" -BackgroundColor Green -ForegroundColor Red
    }
    $null = start-Process -PassThru explorer $Root
} else {
    Write-Host "`nAn error accured, couldnt download any file" -BackgroundColor Red -ForegroundColor Black
}


Stop-Transcript | Out-Null