Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web

function Connect-MICore {
    param(
        [Parameter(Mandatory=$true)][string]$coreHost,
        [Parameter(Mandatory=$true)][string]$apiUser
    )
    $apiPass = Read-Host -prompt "Password for Core API"
    $tempArray = $apiPass.ToCharArray() | % {[byte] $_}
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($tempArray, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    New-Item -Path $global:registryURL -Force | Out-null
    New-ItemProperty -Path $global:registryURL -Name CoreHost -Value $coreHost -Force | Out-Null
    New-ItemProperty -Path $global:registryURL -Name ApiUser -Value $apiUser -Force | Out-Null
    New-ItemProperty -Path $global:registryURL -Name ApiPass -Value $encrypted -Force | Out-Null
    $global:coreHost = $coreHost
    $global:apiCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($apiUser + ":" + $apiPass))
    Write-host "Connected to $global:coreHost"
}

function Disconnect-MICore {
    Remove-ItemProperty -Path $global:registryURL -Name CoreHost | Out-Null
    Remove-ItemProperty -Path $global:registryURL -Name ApiUser | Out-Null
    Remove-ItemProperty -Path $global:registryURL -Name ApiPass | Out-Null
    $global:coreHost = $null
    $global:apiCredentials = $null
}

function Get-MIDeviceLabel {
    param(
        [Parameter(Mandatory=$true)][string]$Uuid
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $global:coreHost + '/api/v2/devices/' + $Uuid + '/labels?adminDeviceSpaceId=1'
    $uri = [uri]::EscapeUriString($uri)
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredentials"}
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results
}

function Add-MIDeviceLabel {
    param(
        [Parameter(Mandatory=$true)][string]$Uuid,
        [Parameter(Mandatory=$true)][string]$name
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $global:coreHost + '/api/v2/devices/labels/' + $name + '/add?adminDeviceSpaceId=1'
    $body = $jsonBlock + '{"deviceUuids": ["' + $Uuid + '"]}'
    $uri = [uri]::EscapeUriString($uri)
        $webresponse = invoke-webrequest -uri $uri -headers @{"Authorization" = "Basic $global:apiCredentials"} -body $body -method PUT -contentType application/json
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results.records.device
}

function Copy-MIDeviceLabels {
    param(
        [Parameter(Mandatory=$true,ParameterSetName="fromDevice")][string]$uuid,
        [Parameter(Mandatory=$true,ParameterSetName="fromFile")][string]$file,
        [Parameter(Mandatory=$true)][string]$target
    )
    if ($uuid) {
        $labels = (Get-MIDeviceLabel $uuid | where {$_.staticLabel -eq $True}).Name
    } else {
        $labels = (Get-Content -Path $file)
    }
    $report = @()
    $labelCount = 0
    foreach ($label in $labels) {
        $result = Add-MIDeviceLabel $target $label
        $resultHash = [ordered]@{
            name = $label
            message = $result.message
            failureCode = $result.failureCode
            }
        $PSresult = New-Object PSObject -Property $resultHash
        $report += $PSresult
        $labelCount++
        Write-Progress -Activity "Copying label $label" -Status "$labelCount of $($labels.Count) copied" -PercentComplete ($labelCount/($labels.Count)*100)
    }
    $report
}

function Get-MIDevice {
    param(
            [Parameter(Mandatory=$false)][string]$uuid
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $global:coreHost + '/api/v1/dm/devices'
    if ($uuid) {
        $uri = $uri + "/" + $uuid
    }
    $uri = [uri]::EscapeUriString($uri)
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredentials"}
    $response = ConvertFrom-JSON $webresponse.Content

    if ($uuid) {
        $response.device
    } else {
        $response.devices.device
    }
}

# get values for API access
$global:registryURL = "HKCU:\Software\MobileIron\MICore.PSHelper"
$registryKey = (Get-ItemProperty -Path $registryURL -ErrorAction SilentlyContinue)
if ($registryKey -eq $null) {
    Write-Warning "Autoconnect failed.  API key not found in registry.  Use Connect-MICore to connect manually."
} else {
    $encrypted = $registryKey.apiPass
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decrypted | % { $apiPass += [char] $_} | Out-Null
    $global:coreHost = $registryKey.CoreHost
    $global:apiCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($registryKey.apiUser + ":" + $apiPass))
    Write-host "Connected to $global:coreHost"
}
Write-host "Cmdlets added: $(Get-Command | where {$_.ModuleName -eq "MICore.PSHelper"})"