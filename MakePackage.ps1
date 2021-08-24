#Import-Module $PSScriptRoot\CyberFunctions.psm1

function Get-Tools {
    $global:Root = Get-Folder
    start-Transcript -path $Root\MakePackage.Log -Force -append
    (Get-Item $Root\MakePackage.Log).Attributes += 'Hidden'
    $ToolsList = @("Goddi", "NTDSAudit", "PingCastle", "Testimo", "CyberAuditLiteFD", "CyberFunctions")
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
            "Testimo"{
                $ToolURL = "https://github.com/maros17/GoGetCyberAuditLite/raw/main/TestimoAndDependecies.zip"
            }
            "CyberAuditLiteFD" {
                $ToolURL = "https://github.com/maros17/GoGetCyberAuditLite/blob/main/CyberAuditLiteFD.ps1" 
            }
            "CyberFunctions" {
                $ToolURL = "https://github.com/maros17/GoGetCyberAuditLite/blob/main/CyberFunctions.psm1"
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
        dl $ToolURL $ToolLocalPath
        if ($NeedToExpand) {
        Write-Host "Expanding $ToolName archive" -ForegroundColor Magenta            
            $ToolDirectory = Split-Path $ToolLocalPath -Parent
            Expand-Archive -Path $ToolLocalPath -DestinationPath $ToolDirectory -Force
            Remove-Item $ToolLocalPath
        }
    }
}
function Compress-All {
    $ContentToCompress =  Get-ChildItem -Path $Root -Exclude "*.log" 
    $ContentToCompress | Compress-Archive -DestinationPath $Root\CyberAuditLiteFD.zip -Verbose -Force 
    $ContentToCompress | Remove-Item -Force -Recurse
}
function dl($url, $to) {
    try {
        $wc = New-Object Net.Webclient
        $wc.headers.add('Referer', (strip_filename $url))
        $wc.Headers.Add('User-Agent', (Get-UserAgent))
        $wc.downloadFile($url, $to)
    } catch {
        Write-Host "ERROR: Couldnt download from $url" -ForegroundColor Red
    }
}
function Get-UserAgent() {
    return "CyberAuditTool/1.0 (+http://cyberaudittool.c1.biz/) PowerShell/$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) (Windows NT $([System.Environment]::OSVersion.Version.Major).$([System.Environment]::OSVersion.Version.Minor); $(if($env:PROCESSOR_ARCHITECTURE -eq 'AMD64'){'Win64; x64; '})$(if($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64'){'WOW64; '})$PSEdition)"
}
function fname($path) { split-path $path -leaf }
function strip_filename($path) { $path -replace [regex]::escape((fname $path)) }

Function Get-Folder($initialDirectory) {
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowserDialog.RootFolder = 'MyComputer'
    if ($initialDirectory) { $FolderBrowserDialog.SelectedPath = $initialDirectory }
    $Topmost = New-Object System.Windows.Forms.Form
    $Topmost.TopMost = $True
   $Topmost.MinimizeBox = $True
#$FolderBrowserDialog.
    if ( $FolderBrowserDialog.ShowDialog($Topmost) -eq "Cancel")
        {Write-Error "ERROR: Cannot continue without a folder" -ErrorAction Stop}
    return $FolderBrowserDialog.SelectedPath
}
Get-Tools
Compress-All

Stop-Transcript | Out-Null