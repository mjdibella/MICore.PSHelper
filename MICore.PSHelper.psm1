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

function Connect-MICore {
    param(
        [Parameter(Mandatory=$true)][string]$coreHost,
        [Parameter(Mandatory=$true)][string]$apiUser
    )
    $apiPass = Read-HostSecure -prompt "Password"
    $global:coreHost = $coreHost
    $global:apiCredential = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($apiUser + ":" + $apiPass))
    $tempArray = $global:apiCredential.ToCharArray() | % {[byte] $_}
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($tempArray, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    New-Item -Path $global:registryURL -Force | Out-null
    New-ItemProperty -Path $global:registryURL -Name CoreHost -Value $coreHost -Force | Out-Null
    New-ItemProperty -Path $global:registryURL -Name ApiCredential -Value $encrypted | Out-Null
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
        [parameter(Mandatory=$false,ValueFromPipeline=$true)][string[]]$name
    )
    begin {
        $body = $jsonBlock + '{"deviceUuids": ["' + $Uuid + '"]}'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $report = @()
        $labelCount = 0
    }
    process {
        if ($name) {
            foreach ($label in $name) {
                $uri = 'https://' + $global:coreHost + '/api/v2/devices/labels/' + $label + '/add?adminDeviceSpaceId=1'
                $uri = [uri]::EscapeUriString($uri)
                $webresponse = invoke-webrequest -uri $uri -headers @{"Authorization" = "Basic $global:apiCredential"} -body $body -method PUT -contentType application/json
                $response = ConvertFrom-JSON $webresponse.Content
                $resultHash = [ordered]@{
                    label = $response.results.records.label
                    message = $response.results.records.device.message
                    failureCode = $response.results.records.device.failureCode
                }
                $PSresult = New-Object PSObject -Property $resultHash
                $report += $PSresult
            }
        }
    }
    end {
        $report
    }
}

function Remove-MIDeviceLabel {
    param(
        [Parameter(Mandatory=$true)][string]$Uuid,
        [parameter(Mandatory=$false,ValueFromPipeline=$true)][string[]]$name
    )
    begin {
        $body = $jsonBlock + '{"deviceUuids": ["' + $Uuid + '"]}'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $report = @()
    }
    process {
        if ($name) {
            foreach ($label in $name) {
                $uri = 'https://' + $global:coreHost + '/api/v2/devices/labels/' + $label + '/remove?adminDeviceSpaceId=1'
                $uri = [uri]::EscapeUriString($uri)
                $webresponse = invoke-webrequest -uri $uri -headers @{"Authorization" = "Basic $global:apiCredential"} -body $body -method PUT -contentType application/json
                $response = ConvertFrom-JSON $webresponse.Content
                $resultHash = [ordered]@{
                    label = $label
                    successful = $response.successful
                }
                $PSresult = New-Object PSObject -Property $resultHash
                $report += $PSresult
            }
        }
    }
    end {
        $report
    }
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

function New-MIDevice {
    param(
        [Parameter(Mandatory=$true,ParameterSetName="fromTemplate")][string]$uuid,
        [Parameter(Mandatory=$false,ParameterSetName="fromTemplate")][switch]$noLabels,
        [Parameter(Mandatory=$true,ParameterSetName="fromParams")][string]$phoneNumber,
        [Parameter(Mandatory=$true,ParameterSetName="fromParams")][string]$userId,
        [Parameter(Mandatory=$false)][string]$operator,
        [Parameter(Mandatory=$true,ParameterSetName="fromParams")][boolean]$isEmployeeOwned,
        [Parameter(Mandatory=$true,ParameterSetName="fromParams")][string]$platform,
        [Parameter(Mandatory=$true,ParameterSetName="fromParams")][string]$deviceType,
        [Parameter(Mandatory=$false)][switch]$localUser,
        [Parameter(Mandatory=$false)][string]$userFirstName,
        [Parameter(Mandatory=$false)][string]$userLastName,
        [Parameter(Mandatory=$false)][string]$userEmailAddress,
        [Parameter(Mandatory=$false)][switch]$notifyUser,
        [Parameter(Mandatory=$false)][switch]$notifyuserbysms,
        [Parameter(Mandatory=$false)][string]$countryCode = "1"

    )
    if ($uuid) {
        # create new device from the values of the existing device
        $device = get-MIDevice -uuid $uuid
        if ($device) {
            if (-Not $platfrom) {
                $platformName = ((Get-MIDevice -uuid ef9c1a62-446b-4fb0-a333-5cd4658c6475).details.entry | where {$_.key -eq "platform"}).Value
                switch ($platformName) {
                    "iPhone" {$platform = "I"}
                    "iOS" {$platform = "I"}
                    "macOS" {$platform = "I"}
                    "Android" {$platform = "I"}
                    default {
                        $windowsType = ((Get-MIDevice).details.entry | where {$_.key -eq "wp_os_platform"}).value
                        if ($windowsType) {
                            $isWindowsPhone = ((Get-MIDevice).details.entry | where {$_.key -eq "wp_phone"}).value
                            if ($isWindowsPhone = "True") {
                                $platform = "M"
                            } else {
                                $platform = "E"
                            }
                        }
                    }
                }
            }
            if (-Not $phoneNumber) {
                $phoneNumber = $device.currentPhoneNumber
            }
            if (-Not $userId) {
                $userId = $device.principal
            }
            if (-Not $operator) {
                $operator = $device.operator
            }
            if (-Not $isEmployeeOwned) {
                $isEmployeeOwned = $device.employeeOwned
            }
            if (-Not $deviceType) {
                if ($phoneNumber -eq "PDA") {
                    $deviceType = "PDA"
                } else {
                    $deviceType = "Phone"
                }
            }
        }
    }
    $uri = 'https://' + $global:coreHost + '/api/v1/dm/register'
    $uri = $uri + '?phoneNumber=' + $($phoneNumber -replace "[^0-9]")
    $uri = $uri + '&userId=' + $userId
    if ($operator) {
        $uri = $uri + '&operator=' + [System.Web.HttpUtility]::UrlEncode($operator)
    }
    $uri = $uri + '&isEmployeeOwned=' + $isEmployeeOwned
    $uri = $uri + '&platform=' + [System.Web.HttpUtility]::UrlEncode($platform)
    $uri = $uri + '&deviceType=' + [System.Web.HttpUtility]::UrlEncode($deviceType)
    $uri = $uri + '&importUserFromLdap=' + (-Not $localUser)
    if ($userFirstName) {
        $uri = $uri + '&userFirstName=' + [System.Web.HttpUtility]::UrlEncode($userFirstName)
    }
    if ($userLastName) {
        $uri = $uri + '&userLastName=' + [System.Web.HttpUtility]::UrlEncode($userLastName)
    }
    if ($userEmailAddress) {
        $uri = $uri + '&userEmailAddress=' + [System.Web.HttpUtility]::UrlEncode($userEmailAddress)
    }
    $uri = $uri + '&notifyuser=' + $notifyuser
    $uri = $uri + '&notifyuserbysms=' + $notifyuserbysms
    $uri = $uri + '&countryCode=' + $countryCode
    try {
        $webresponse = invoke-webrequest -uri $uri -headers @{"Authorization" = "Basic $global:apiCredential"} -method PUT 
        $registerResult = (ConvertFrom-JSON $webresponse.Content).registration
        if (($registerResult.status -eq 'SUCESS') -or ($registerResult.status -eq 'SUCCESS')) {
            if (($uuid) -and (-Not $noLabels)) {
                $labelResult = Copy-MIDeviceLabels -uuid $uuid -target $registerResult.deviceUuid
                $registerResult | Add-member -NotePropertyName labelResult -NotePropertyValue $labelResult
            }
        }
        $registerResult
    } catch {
        Set-RESTErrorResponse
    }
}

function Set-RESTErrorResponse {
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();
    $global:responseError = (ConvertFrom-JSON $global:responsebody).messages
    $global:responseError
    break
}

function Get-MICommand {
    Get-Command | where {$_.ModuleName -eq "MICore.PSHelper"}
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
    $decrypted | % { $apiBase64 += [char] $_} | Out-Null
    $global:apiCredential = $apiBase64
    Write-host "Connected to $global:coreHost"
}
Write-host "Cmdlets added: $(Get-Command | where {$_.ModuleName -eq "MICore.PSHelper"})`n"