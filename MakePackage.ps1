start-Transcript -path $PSScriptRoot\MakePackage.Log -Force -append
#Import-Module $PSScriptRoot\CyberFunctions.psm1

function Get-Tools {
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
            "CyberAuditLiteFD"{
                $ToolURL = "https://github.com/maros17/GoGetCyberAuditLite/blob/main/CyberAuditLiteFD.ps1" 
            }
            "CyberFunctions" {
                $ToolURL = "https://github.com/maros17/GoGetCyberAuditLite/blob/main/CyberFunctions.psm1"
            }
            Default {}
        }
        $ToolEXEName = Split-Path $ToolURL -Leaf
        if ($ToolEXEName -notmatch "*.ps"){
            New-Item  -Path "$PSScriptRoot\$ToolName"  -ItemType "Directory" -Force | out-null
            $ToolLocalPath = "$PSScriptRoot\$ToolName\$ToolEXEName"
        }else {
            $ToolLocalPath = "$PSScriptRoot\$ToolEXEName"            
        }
        dl $ToolURL $ToolLocalPath
        if ($NeedToExpand){
            $ToolDirectory = Split-Path $ToolLocalPath -Parent
            Expand-Archive -Path $ToolLocalPath -DestinationPath $ToolDirectory -Force
            Remove-Item $ToolLocalPath
        }
    }
}
function Compress-All {
    
    
}
function dl($url, $to) {
    $wc = New-Object Net.Webclient
    $wc.headers.add('Referer', (strip_filename $url))
    $wc.Headers.Add('User-Agent', (Get-UserAgent))
    $wc.downloadFile($url, $to)
}
Get-Tools

Stop-Transcript | Out-Null