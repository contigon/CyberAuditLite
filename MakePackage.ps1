#Import-Module $PSScriptRoot\CyberFunctions.psm1

function Get-Tools {
    start-Transcript -path $PSScriptRoot\MakePackage.Log -Force -append
    $Root = Get-Folder
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
            "CyberAuditLiteFD" {
                $ToolURL = "https://github.com/maros17/GoGetCyberAuditLite/blob/main/CyberAuditLiteFD.ps1" 
            }
            "CyberFunctions" {
                $ToolURL = "https://github.com/maros17/GoGetCyberAuditLite/blob/main/CyberFunctions.psm1"
            }
            Default {}
        }
        $ToolEXEName = Split-Path $ToolURL -Leaf
        if ($ToolEXEName -notmatch "*.ps") {
            New-Item  -Path "$Root\$ToolName"  -ItemType "Directory" -Force | out-null
            $ToolLocalPath = "$Root\$ToolName\$ToolEXEName"
        } else {
            $ToolLocalPath = "$Root\$ToolEXEName"            
        }
        Write-Host "Downloading $ToolName to $ToolLocalPath" -ForegroundColor Magenta
        dl $ToolURL $ToolLocalPath
        if ($NeedToExpand) {
            $ToolDirectory = Split-Path $ToolLocalPath -Parent
            Expand-Archive -Path $ToolLocalPath -DestinationPath $ToolDirectory -Force
            Remove-Item $ToolLocalPath
        }
    }
}
function Compress-All {
    
    
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

Function Get-Folder($initialDirectory) {
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowserDialog.RootFolder = 'MyComputer'
    if ($initialDirectory) { $FolderBrowserDialog.SelectedPath = $initialDirectory }
    $Topmost = New-Object System.Windows.Forms.Form
    $Topmost.TopMost = $True
    $Topmost.MinimizeBox = $True
    [void] $FolderBrowserDialog.ShowDialog($Topmost) 
    return $FolderBrowserDialog.SelectedPath
}
Get-Tools

Stop-Transcript | Out-Null