Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web

function Connect-MICore {
    param(
        [Parameter(Mandatory=$true)][string]$coreHost,
        [Parameter(Mandatory=$true)][string]$apiUser
    )
    $securedValue = Read-Host -prompt "Password" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
    $apiPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $global:coreHost = $coreHost
    $global:apiCredential = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($apiUser + ":" + $apiPass))
    $tempArray = $global:apiCredential.ToCharArray() | % {[byte] $_}
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($tempArray, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    New-Item -Path $global:registryURL -Force | Out-null
    New-ItemProperty -Path $global:registryURL -Name CoreHost -Value $coreHost -Force | Out-Null
    New-ItemProperty -Path $global:registryURL -Name ApiCredential -Value $encrypted | Out-Null
    Get-MICore
}

function Disconnect-MICore {
    Remove-ItemProperty -Path $global:registryURL -Name CoreHost | Out-Null
    Remove-ItemProperty -Path $global:registryURL -Name ApiCredential | Out-Null
    $global:coreHost = $null
    $global:apiCredential = $null
}

function Get-MICore {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://' + $global:coreHost + '/status/status.html'
    $webresponse = (invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}).Content
    $response = @()
    $response = $webresponse.Split([Environment]::NewLine)
    $hash = [ordered]@{
        Host = $global:coreHost
        Status = $response[0]
        Message = $response[2]
    }
    $result = New-Object PSObject -Property $hash
    $result
}

function Get-MILabel {
    param(
        [Parameter(Mandatory=$false)][string]$labelId
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($labelId) {
        $uri = 'https://' + $global:coreHost + '/api/v2/labels/' + $labelId + '?adminDeviceSpaceId=1'
    } else {
        $uri = 'https://' + $global:coreHost + '/api/v2/labels/label_summary?adminDeviceSpaceId=1'
    }
    $uri = [uri]::EscapeUriString($uri)
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results
}

function New-MIStaticLabel {
    param(
        [parameter(Mandatory=$false,ValueFromPipeline=$true)][string[]]$name,
        [parameter(Mandatory=$false)][string[]]$description
    )
    begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $report = @()
    }
    process {
        if ($name) {
            foreach ($label in $name) {
                $body = '{"name": "' + $name + '","description": "' + $description + '","deviceSpaceId": 1,"static": true}'
                $uri = 'https://' + $global:coreHost + '/api/v2/labels/?adminDeviceSpaceId=1'
                $uri = [uri]::EscapeUriString($uri)
                $webresponse = invoke-webrequest -uri $uri -headers @{"Authorization" = "Basic $global:apiCredential"} -body $body -method POST -contentType application/json
                $response = ConvertFrom-JSON $webresponse.Content
                $resultHash = [ordered]@{
                    id = $response.results.id
                    message = $response.results.name
                    staticLabel = $response.results.staticLabel
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

function Remove-MILabel {
    param(
        [parameter(Mandatory=$false,ValueFromPipeline=$true)][string[]]$labelId,
        [parameter(Mandatory=$true)][string]$reason
    )
    begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $report = @()
    }
    process {
        if ($labelId) {
            foreach ($id in $labelId) {
                $body = '{"reason": "' + $reason + '","labelIds":[' + $labelId + '],"deviceSpaceId": 1}'
                $uri = 'https://' + $global:coreHost + '/api/v2/labels/?adminDeviceSpaceId=1'
                $uri = [uri]::EscapeUriString($uri)
                $webresponse = invoke-webrequest -uri $uri -headers @{"Authorization" = "Basic $global:apiCredential"} -body $body -method DELETE -contentType application/json
                $resultHash = [ordered]@{
                    id = $id
                    reason = $reason
                    statusCode = $webResponse.statusCode
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
        $body = '{"deviceUuids": ["' + $Uuid + '"]}'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $report = @()
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
        $body = '{"deviceUuids": ["' + $Uuid + '"]}'
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
    $content = ConvertFrom-JSON $webresponse.Content
    if ($uuid) {
        $response = $content.device
        $response | Add-member -NotePropertyName labels -NotePropertyValue (Get-MIDeviceLabel -uuid $uuid)

    } else {
        $response = $content.devices.device
    }
    $response
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

function Get-MICatalogApp {
    param(
        [Parameter(Mandatory=$false)][string]$appId
    )
    if ($appId) {
        $uri = "https://$global:coreHost/api/v2/appstore/apps/" + $appId + "?adminDeviceSpaceId=1"
    } else {
        $uri = "https://$global:coreHost/api/v2/appstore/apps?adminDeviceSpaceId=1"
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results
}

function Get-MIUser {
    param(
        [Parameter(Mandatory=$false)][string]$searchString
    )
    if ($searchString) {
        $uri = "https://$global:coreHost/api/v2/authorized/users?query=" + $searchString + "&adminDeviceSpaceId=1"
    } else {
        $uri = "https://$global:coreHost/api/v2/authorized/users?adminDeviceSpaceId=1"
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results
}

function Get-MILdapUser {
    param(
        [Parameter(Mandatory=$true)][string]$searchString
    )
    $uri = "https://$global:coreHost/api/v2/admins/ldap_entities?type=user&query=" + $searchString + "&adminDeviceSpaceId=1"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results
}

function Get-MILdapGroup {
    param(
        [Parameter(Mandatory=$true)][string]$searchString
    )
    $uri = "https://$global:coreHost/api/v2/admins/ldap_entities?type=group&query=" + $searchString + "&adminDeviceSpaceId=1"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results
}

function Get-MILdapOu {
    param(
        [Parameter(Mandatory=$true)][string]$searchString
    )
    $uri = "https://$global:coreHost/api/v2/admins/ldap_entities?type=ou&query=" + $searchString + "&adminDeviceSpaceId=1"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Basic $global:apiCredential"}
    $response = ConvertFrom-JSON $webresponse.Content
    $response.results
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
    Write-host "Connected to MobileIron Core $global:coreHost`n"
}
Write-host "Cmdlets added:`n$(Get-Command | where {$_.ModuleName -eq 'MICore.PSHelper'}).name`n"
