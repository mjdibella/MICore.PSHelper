Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web

function Read-HostSecure {
    param(
        [Parameter(Mandatory=$true)][string]$prompt
    )
    $securedValue = Read-Host -prompt $prompt -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}

function New-SecureItemProperty {
    param(
        [Parameter(Mandatory=$true)][string]$path,
        [Parameter(Mandatory=$true)][string]$name,
        [Parameter(Mandatory=$true)][string]$value
    )
    $tempArray = $value.ToCharArray() | % {[byte] $_}
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($tempArray, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    New-ItemProperty -Path $path -Name $name -Value $encrypted -Force
}

function Unprotect-SecureItemProperty {
    param(
        [Parameter(Mandatory=$true)][string]$value
    )
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decrypted | % { $plaintext += [char] $_} | Out-Null
    $plaintext
}

function Connect-MICore {
    param(
        [Parameter(Mandatory=$true)][string]$coreHost,
        [Parameter(Mandatory=$true)][string]$apiUser
    )
    $apiPass = Read-HostSecure -prompt "Password"
    $global:coreHost = $coreHost
    $global:apiCredential = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($apiUser + ":" + $apiPass))
    New-Item -Path $global:registryURL -Force | Out-null
    New-ItemProperty -Path $global:registryURL -Name CoreHost -Value $coreHost -Force | Out-Null
    New-SecureItemProperty -Path $global:registryURL -Name ApiCredential -Value $apiCredential | Out-Null
    Write-host "Connected to $global:coreHost`n"
}

function Disconnect-MICore {
    Remove-ItemProperty -Path $global:registryURL -Name CoreHost | Out-Null
    Remove-ItemProperty -Path $global:registryURL -Name ApiCredential | Out-Null
    $global:coreHost = $null
    $global:apiCredential = $null
}

function Get-MIDeviceLabel {
    param(
        [Parameter(Mandatory=$true)][string]$Uuid
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $global:coreHost + '/api/v2/devices/' + $Uuid + '/labels?adminDeviceSpaceId=1'
    $uri = [uri]::EscapeUriString($uri)
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
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
        $webresponse = invoke-webrequest -uri $uri -headers @{"Authorization" = "Basic $global:apiCredential"} -body $body -method PUT -contentType application/json
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
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
    $response = ConvertFrom-JSON $webresponse.Content

    if ($uuid) {
        $response.device
    } else {
        $response.devices.device
    }
}

# get values for API access
$global:registryURL = "HKCU:\Software\MobileIron\MICore.PSHelper"
$global:registryKey = (Get-ItemProperty -Path $global:registryURL -ErrorAction SilentlyContinue)
$global:registryKey
if ($global:registryKey -eq $null) {
    Write-Warning "Autoconnect failed.  API key not found in registry.  Use Connect-MICore to connect manually."
} else {
    $global:coreHost = $global:registryKey.CoreHost
    $encrypted = $registryKey.ApiCredential
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decrypted | % { $global:apiCredential += [char] $_} | Out-Null
    Write-host "Connected to $global:coreHost"
}
Write-host "Cmdlets added: $(Get-Command | where {$_.ModuleName -eq "MICore.PSHelper"})`n"