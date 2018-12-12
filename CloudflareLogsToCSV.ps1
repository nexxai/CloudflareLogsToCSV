<#
    .SYNOPSIS
    This script will interact with the CloudFlare API to retrieve the logs for a given period
    .DESCRIPTION
    CloudFlare's API is primarily time-based so this script will allow a user to request logs for a specific period of time.
    .PARAMETER Authorize
    Prompt for your CloudFlare Zone ID, email address, and API key
    .PARAMETER Now
    Grab the most recent logs between now and the beginning of the current hour

    .INPUTS
    None
    .OUTPUTS
    CSV stored in .\logs-<timestamp>.csv
    .NOTES
    Version:        1.0
    Author:         Justin Smith
    Creation Date:  December 5, 2018
    Purpose/Change: Initial script development

    .EXAMPLE
    .\CloudFlareLogsToCSV.ps1 -Authorize
    To set your CloudFlare API zone ID, email address and API key and store them in the registry
    .EXAMPLE
    .\CloudflareLogsToCSV.ps1
    Will prompt you for the hour that you wish to retrieve logs from
    .EXAMPLE
    .\CloudflareLogsToCSV.ps1 -Now
    Will retrieve the logs that accumulated between now and the top of the hour
    .EXAMPLE
    .\CloudflareLogsToCSV.ps1 -Last5
    Will retrieve the logs that accumulated in the last 5 minutes
    .EXAMPLE
    .\CloudflareLogsToCSV.ps1 -Last10
    Will retrieve the logs that accumulated in the last 10 minutes
#>

# Setup the environment
param 
(
    [switch]$Authorize,
    [switch]$Last10,
    [switch]$Last5,
    [switch]$Now
)

function Get-IsValidEmailAddress {
    param
    (
        [Parameter(ValueFromPipeline = $true)][string]$PassedEmailAddress
    )

    if ($null -eq $PassedEmailAddress) {
        return $false
    }

    $IsValidEmailAddress = $true
    try {
        New-Object System.Net.Mail.MailAddress($PassedEmailAddress)
    }
    catch {
        $IsValidEmailAddress = $false
    }

    return $IsValidEmailAddress
}

function Get-IsValidAPIKey {
    param
    (
        [string]$PassedAPIKey
    )

    if ($null -eq $PassedAPIKey) {
        return $false
    }
    $IsValidAPIKey = $false

    # API Keys are given in the format of:
    # - 37 characters
    # - only hexadecimal (0 to 9, and A to F)
    if ($PassedAPIKey -Match '^([0-9a-fA-F]{37}){1}$') {
        $IsValidAPIKey = $true
    }

    return $IsValidAPIKey
}

function Get-IsValidZone {
    param
    (
        [string]$PassedZone
    )

    if ($null -eq $PassedZone) {
        return $false
    }
    $IsValidZone = $false

    # Zone IDs are given in the format of:
    # - 32 characters
    # - only hexadecimal (0 to 9, and A to F)
    if ($PassedZone -Match '^([0-9a-fA-F]{32}){1}$') {
        $IsValidZone = $true
    }

    return $IsValidZone
}

function Set-APICredentials {
    Write-Host
    Write-Host "Please provide the email address associated with your Cloudflare account"
    Write-Host "and the API key and zone ID from the domain you wish to retrieve logs from"
    Write-Host "by opening the Cloudflare dashboard, choosing the correct domain, and"
    Write-Host "selecting 'Get your API key' underneath the Zone ID"
    Write-Host

    $validZone = $false
    do {
        $cloudflareZone = Read-Host "Cloudflare Zone ID"

        # Get-IsValidZone returns 'true' if the Zone is formatted 
        # correctly, or 'false' if not
        $validZone = Get-IsValidZone($cloudflareZone)
    }
    # Loop until the user gives us a properly formatted email address
    until ($validZone)

    $validEmailAddress = $false
    do {
        $cloudflareEmail = Read-Host "Cloudflare Email Address"

        # Get-IsValidEmailAddress returns 'true' if the email is formatted 
        # correctly, or 'false' if not
        $validEmailAddress = Get-IsValidEmailAddress($cloudflareEmail)
    }
    # Loop until the user gives us a properly formatted email address
    until ($validEmailAddress)
      
    $validAPIKey = $false
    do {
        $cloudflareToken = Read-Host "Cloudflare API Key"

        # Get-IsValidAPIKey returns 'true' if the API Key is formatted 
        # correctly, or 'false' if not
        $validAPIKey = Get-IsValidAPIKey($cloudflareToken)
    }
    # Loop until the user gives us a properly formatted email address
    until ($validAPIKey)

    if (!(Test-Path $registryRootPath)) {
        New-Item -Path $registryRootPath -Force | Out-Null
    }
    if (!(Test-Path $registrySettingsPath)) {
        New-Item -Path $registrySettingsPath -Force | Out-Null
    }

    New-ItemProperty -Path $registrySettingsPath -Name Email -Value $cloudflareEmail -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registrySettingsPath -Name Token -Value $cloudflareToken -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registrySettingsPath -Name Zone -Value $cloudflareZone -PropertyType String -Force | Out-Null

    Write-Host
}

function Get-IsAPIKeyAuthorized {
    # Keep looping through this code until the credentials the user provides are accepted by Cloudflare
    do {
        try { 
            # Assume everything is correct unless an exception is caught
            $success = $true

            $nowStart = [Xml.XmlConvert]::ToString((get-date).AddMinutes(-5), [Xml.XmlDateTimeSerializationMode]::Utc)
            $nowEnd = [Xml.XmlConvert]::ToString((get-date).AddMinutes(-5).AddMilliseconds(10), [Xml.XmlDateTimeSerializationMode]::Utc)

            # Check the API and see if our credentials are authorized
            $headers = Set-HTTPHeaders
            $response = Invoke-WebRequest -Uri "https://api.cloudflare.com/client/v4/zones/$($zone)/logs/received?start=$($nowStart)&end=$($nowEnd)" -Headers $headers
        }
        # If an exception is caught, it's likely due to the fact that our credentials are wrong
        # so prompt the user to re-enter them
        catch { 
            Write-Host "Cloudflare credentials were not accepted."
            Set-APICredentials
            $success = $false
        } 
    } 
    until ($success -eq $true)

    # We've made it this far so we know our credentials are good.  Continue on.
    return $success
}

function Set-HTTPHeaders {
    # Get the currently set values for the zone, email address and token from the registry
    $authEmail = (Get-ItemProperty -Path $registrySettingsPath).Email
    $authToken = (Get-ItemProperty -Path $registrySettingsPath).Token
    Set-Variable -Name "zone" -Value (Get-ItemProperty -Path $registrySettingsPath).Zone -Scope Global

    # Set the HTTP headers appropriately
    $headers = @{}
    $headers.add("X-Auth-Email", $authEmail)
    $headers.add("X-Auth-Key", $authToken)

    return $headers
}

# Configuration
Set-Variable -Name "registryRootPath" -Value "HKCU:\Software\nexxai" -Scope Global
Set-Variable -Name "registrySettingsPath" -Value "HKCU:\Software\nexxai\CloudflareLogsToCSV" -Scope Global

# This is a simple array of ASNs that you want to ignore in your logs, with each
# ASN wrapped in single quotations, and separated by commas
#
# For example, maybe you want to ignore requests coming from your own network
# or a customer/client's
#
# Formatting: 
# '12345',
# '6789',
# '9876'
$allowedASNs = {
}

# This is a simple array of User-Agents or portions of a User-Agent that you 
# want to ignore in your logs with each User-Agent or portion of a User-Agent 
# wrapped in single quotations, and separated by commas.
#
# For example, maybe you want to ignore requests coming from your own network
# or a customer/client's
#
# Formatting:
# 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
# 'Chrome/60.0',                    <---- Ignore all Chrome v60 entries
# 'Android',                        <---- Ignore all Android access attempts
# 'okhttp'                          <---- Ignore all Square payment service access
$allowedUserAgents = {
    'okhttp'
}

if ($Authorize) {
    Set-APICredentials
}

if (!(Get-ItemProperty -Path $registrySettingsPath -Name Zone -ErrorAction SilentlyContinue)) {
    Write-Host "CloudFlare Zone ID not found."
    Set-APICredentials
}

if (!(Get-ItemProperty -Path $registrySettingsPath -Name Email -ErrorAction SilentlyContinue)) {
    Write-Host "CloudFlare-associated email address not found."
    Set-APICredentials
}

if (!(Get-ItemProperty -Path $registrySettingsPath -Name Token -ErrorAction SilentlyContinue)) {
    Write-Host "CloudFlare API token not found."
    Set-APICredentials
}

# Check to make sure if user's API Key is valid and keep asking until Cloudflare accepts the entered data
do {
    [bool]$userIsAuthorized = Get-IsAPIKeyAuthorized
}
until ($userIsAuthorized)

$CSVFile = ".\logs-$(Get-Date -Format yyy-MM-dd-hhmmss).csv"

if ($Now) {
    # Cloudflare only offers logs more than 1 minute old; request 1 minutes and 5 seconds ago to account for clock shift
    $start = (Get-Date -Hour (Get-Date).Hour -Minute 0 -Second 0 -Millisecond 0)
    $end = (Get-Date -Millisecond 0).AddMinutes(-1).AddSeconds(-5)
} elseif ($Last10) {
    $start = (Get-Date).AddMinutes(-10)
    $end = (Get-Date -Millisecond 0).AddMinutes(-1).AddSeconds(-5)
} elseif ($Last5) {
    $start = (Get-Date).AddMinutes(-5)
    $end = (Get-Date -Millisecond 0).AddMinutes(-1).AddSeconds(-5)
} else {
    Write-Host
    Write-Host "Cloudflare only allows downloading 1 hour of logs at a time"
    Write-Host "Enter the date and time of when you want the logs to start"
    Write-Host "For example, if you want the logs from December 25 between 1PM and 2PM,"
    Write-Host "enter something like 'December 25, 1pm'"
    Write-Host
    Write-Host "NOTE: Date entered will automatically be converted to UTC"
    Write-Host
    do {
        $start = Read-Host "Start Date/Time"
        $start = (Get-Date -Date "$($start)")
        if ($start -gt (Get-Date)) {
            Write-Host "Date must be in the past.  Please enter a valid date."
        }
    } until ($start -lt (Get-Date))   
    $end = $start.AddHours(1)
}

$startDate = [Xml.XmlConvert]::ToString($start.ToUniversalTime(), [Xml.XmlDateTimeSerializationMode]::Utc)
$endDate = [Xml.XmlConvert]::ToString($end.ToUniversalTime(), [Xml.XmlDateTimeSerializationMode]::Utc)

# Starting the actual work
Write-Host "Obtaining logs.  Please wait."

# Create the column headers
$firstLine = "Timestamp,IP,Country,Device Type,User Agent,SSL Cipher,SSL Protocol,Source Port,Edge Status Code,Origin Status Code,Referer,Host,Request URI,RayID,EdgeRateLimitID,WAFRuleID,CacheCacheStatus"
$firstLine | Add-Content -Path $CSVFile

# Enforce TLS1.2 (Cloudflare requires this)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Grab the respective hour from the API
$headers = Set-HTTPHeaders
$response = Invoke-WebRequest -Uri "https://api.cloudflare.com/client/v4/zones/$($zone)/logs/received?start=$($startDate)&end=$($endDate)&fields=ClientASN,ClientCountry,ClientDeviceType,ClientIP,ClientRequestUserAgent,ClientSSLCipher,ClientSSLProtocol,ClientSrcPort,ClientRequestURI,OriginResponseStatus,ClientRequestReferer,ClientRequestHost,EdgeStartTimestamp,EdgeResponseStatus,RayID,EdgeRateLimitID,WAFRuleID,CacheCacheStatus&timestamps=rfc3339" -Headers $headers

# Take the big blob of data and format it into single lines
$linePerEntry = ($response.content -Split '[\r\n]')

# Debug info 
$totalRows = $linePerEntry.count
Write-Host "$($totalRows) rows received"
$lineCount = 0
$startTime = Get-Date

foreach ($line in $linePerEntry) {
    # Convert the given line from JSON to CSV-format
    $CSVData = $line | ConvertFrom-Json

    # Get the ASN from the line for comparison
    $ClientASN = $CSVData.ClientASN
    
    # Remove any commas from the user-agent as most CSV readers (*glares at MS Excel*)
    # see the comma and immediately stop processing the rest of the entry as a single
    # field entry, even if wrapped in quotation marks.
    $ClientRequestUserAgent = $CSVData.ClientRequestUserAgent -Replace ',', ''

    # Ignore any of the ASNs and/or User-Agents that we defined to ignore above
    if ($allowedASNs -NotContains $ClientASN -And $ClientRequestUserAgent -NotContains $allowedUserAgents) {
        # Get rid of any commas which will causes incorrect columning in a CSV
        $ClientIP = $CSVData.ClientIP
        $ClientCountry = $CSVData.ClientCountry
        $ClientDeviceType = $CSVData.ClientDeviceType -Replace ',', ''
        $ClientSSLCipher = $CSVData.ClientSSLCipher
        $ClientSSLProtocol = $CSVData.ClientSSLProtocol
        $ClientSrcPort = $CSVData.ClientSrcPort
        $ClientRequestURI = $CSVData.ClientRequestURI -Replace ',', ''
        $OriginResponseStatus = $CSVData.OriginResponseStatus
        $ClientRequestReferer = $CSVData.ClientRequestReferer -Replace ',', ''
        $ClientRequestHost = $CSVData.ClientRequestHost
        $EdgeStartTimestamp = $CSVData.EdgeStartTimestamp
        $EdgeResponseStatus = $CSVData.EdgeResponseStatus
        $RayID = $CSVData.RayID
        $EdgeRateLimitID = $CSVData.EdgeRateLimitID
        $WAFRuleID = $CSVData.WAFRuleID
        $CacheCacheStatus = $CSVData.CacheCacheStatus    
        # Define what a new line looks like by setting the column headers
        $newLine = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16}" -f $EdgeStartTimestamp, $ClientIP, $ClientCountry, $ClientDeviceType, $ClientRequestUserAgent, $ClientSSLCipher, $ClientSSLProtocol, $ClientSrcPort, $EdgeResponseStatus, $OriginResponseStatus, $ClientRequestReferer, $ClientRequestHost, $ClientRequestURI, $RayID, $EdgeRateLimitID, $WAFRuleID, $CacheCacheStatus
    
        # Write the line to the file
        $newLine | Add-Content -Path $CSVFile

        $lineCount++
    }  

    # Prepare the progress bar values
    $percentComplete = $lineCount / $totalRows * 100
    $elapsedTime = New-TimeSpan -Start $startTime -End $(Get-Date)
    $totalTime = ($elapsedTime.TotalSeconds) / ($percentComplete / 100)

    # ...do some math
    $etaElapsed = (Get-Date) - $startTime
    $etaSeconds = New-TimeSpan -Seconds ($totalTime - $etaElapsed.TotalSeconds)
    
    # ...format the strings
    $ETA = "{0:hh}h{0:mm}m{0:ss}s" -f $etaSeconds
    $elapsed = "{0:hh}h{0:mm}m{0:ss}s" -f $elapsedTime
    $processedPercent = [Math]::Round($percentComplete, 2)

    # Until we've passed the first second, we'll get a divide by 0 error unless we just divide by 1
    if ($elapsedTime.Seconds -gt 0) {
        $rps = [Math]::Round($lineCount / ($elapsedTime.Seconds), 0)
    } else {
        $rps = [Math]::Round($lineCount / 1, 0)
    }
    
    # ...and now update the progress bar
    Write-Progress -Activity "Processing logs" -status "$($lineCount) lines processed ($($processedPercent)% / $($rps) rows per second) // Elapsed: $($elapsed) // ETA: $($ETA)" -percentComplete ($percentComplete)
}

Write-Host "Complete."
Write-Host
