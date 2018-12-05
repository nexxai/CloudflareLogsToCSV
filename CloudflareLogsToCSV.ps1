<#
    .SYNOPSIS
    This script will interact with the CloudFlare API to retrieve the logs for a given period
    .DESCRIPTION
    CloudFlare's API is primarily time-based so this script will allow a user to request logs for a specific period of time.
    .PARAMETER Year
    The 4-digit year
    .PARAMETER Month
    The 2-digit month
    .PARAMETER Day
    The 2-digit day
    .PARAMETER Hour
    The 2-digit hour in 24-hour local time
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
    .\CloudFlare.ps1 -Authorize
    To set your CloudFlare API zone ID, email address, and API key and store them in the registry
    .EXAMPLE
    .\Cloudflare.ps1
    Will retrieve the logs that accumulated between now and the top of the hour
    .EXAMPLE
    .\CloudFlare.ps1 -Hour 17
    Will retrieve the logs for the entriety of 5PM local time
    .EXAMPLE
    .\CloudFlare.ps1 -Hour 17 -Day 1
    Will retrieve the logs for the entriety of 5PM local time on the first day of the month
    .EXAMPLE
    .\CloudFlare.ps1 -Hour 17 -Month 5 -Day 1
    Will retrieve the logs for the entriety of 5PM local time on the first day of May
    .EXAMPLE
    .\CloudFlare.ps1 -Hour 17 -Month 5 -Day 1 -Year 2000
    Will retrieve the logs for the entriety of 5PM local time on the first day of May 2000
#>

# Setup the environment
param (
    [int]$Year,
    [int]$Month,
    [int]$Day,
    [int]$Hour,
    [string]$Email,
    [string]$Token,
    [switch]$Authorize
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
    do {
        try { 
            $success = $true
            $headers = Set-HTTPHeaders
            $response = Invoke-WebRequest -Uri "https://api.cloudflare.com/client/v4/zones/$($zone)/logs/received?start=$([Xml.XmlConvert]::ToString((get-date).AddMinutes(-5),[Xml.XmlDateTimeSerializationMode]::Utc))&end=$([Xml.XmlConvert]::ToString((get-date).AddMinutes(-5),[Xml.XmlDateTimeSerializationMode]::Utc))&fields=ClientASN,ClientCountry,ClientDeviceType,ClientIP,ClientIPClass,ClientRequestUserAgent,ClientSSLCipher,ClientSSLProtocol,ClientSrcPort,ClientRequestURI,OriginResponseStatus,ClientRequestReferer,ClientRequestHost,EdgeStartTimestamp,EdgeResponseStatus&timestamps=rfc3339" -Headers $headers
        }
        catch { 
            Write-Host "Cloudflare credentials were not accepted."
            Set-APICredentials
            $success = $false
        } 
    } 
    until ($success -eq $true)

    return $success
}

function Set-HTTPHeaders {
    # Get and set the HTTP headers 
    $authEmail = (Get-ItemProperty -Path $registrySettingsPath).Email
    $authToken = (Get-ItemProperty -Path $registrySettingsPath).Token
    Set-Variable -Name "zone" -Value (Get-ItemProperty -Path $registrySettingsPath).Zone -Scope Global

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

# Check to make sure if user's API Key is valid
do {
    $checkAuthorization = Get-IsAPIKeyAuthorized
}
until ($checkAuthorization)

$CSVFile = ".\logs-$(Get-Date -Format yyy-MM-dd-hhmmss).csv"

# No year was given; use the current year in 4-digit format
if(!$year) {
    $year = (Get-Date).year.ToString("0000")
}

# No month was given; use the current month in 2-digit format
if (!$month) {
    $month = (Get-Date).month.ToString("00")
}

# No day was given; use the current day in 2-digit format
if (!$day) {
    $day = (Get-Date).day.ToString("00")
}

# If the user specified an hour in the -Hour parameter
if ($hour) {
    # Start building the query string parameters
    $hourLoopStart = $hour
    $hourLoopEnd = $hour
    # UTC gives us -7 for example, but we need to invert it (add 7 hours)
    $hour = $hour + ((Get-TimeZone).BaseUTCOffset.TotalHours * -1)

    # If we're specifically looking for the current hour in the current day
    if ($hour -eq (Get-Date).ToUniversalTime().hour -And $day -eq (Get-Date).day) {
        # Cloudflare doesn't publish logs for 1 minute so start that far back
        $minuteEnd = (Get-Date).AddMinutes(-2).minute.ToString("00")

        # The script was started in the first 1 minute of the hour; so just get all of last hour
        if ($minuteEnd -lt 0) {
            $hour -= 1
            Write-Host "Minute wrap-around"
            $hourLoopStart = $hour - 1
            $hourLoopEnd = $hour - 1
        }

    # We're looking at the current day, but not the current hour, so we don't need to worry about going back 5 minutes
    } else {
        $minuteEnd = "59"
    }
# The user did not specify an hour in the -Hour parameter; only the day
} else {
    if ($day -eq (Get-Date).day) {
        # Cloudflare doesn't publish logs for 1 minute so start that far back
        $minuteEnd = (Get-Date).AddMinutes(-2).minute.ToString("00")

        # The script was started in the first 1 minute of the hour; so just get all of last hour
        if ($minuteEnd -lt 0) {
            $hourLoopStart = $hour - 1
            $hourLoopEnd = $hour - 1
        }

        $hour = (Get-Date).ToUniversalTime().hour.ToString("00")

        # We're looking at the current day, but not the current hour, so we don't need to worry about going back 5 minutes
    }
    else {
        $hourLoopStart = 0
        $hourLoopEnd = 23
        $minuteEnd = "59"
    }
}

# Make sure the date is left padded to contain exactly 2 digits
$date = $day.ToString("00")

# Create the column headers
$firstLine = "Timestamp,ASN,IP,IP Class,Country,Device Type,User Agent,SSL Cipher,SSL Protocol,Source Port,Edge Status Code,Origin Status Code,Referer,Host,Request URI"
$firstLine | Add-Content -Path $CSVFile

# Loop through each of the hours throughout the day
for ($i = $hourLoopStart; $i -le $hourLoopEnd; $i++) {
    if ($hour) {
        $getHour = $hour.ToString("00")
    } else {
        $getHour = $i
    }

    # Log to the screen so we know where we are in the process
    Write-Host "Log Range: $($year)-$($month)-$($date)T$($getHour):00:00Z - $($year)-$($month)-$($date)T$($getHour):$($minuteEnd):59Z"
    
    Write-Host "URL: https://api.cloudflare.com/client/v4/zones/$($zone)/logs/received?start=$($year)-$($month)-$($date)T$($getHour):00:00Z&end=$($year)-$($month)-$($date)T$($getHour):$($minuteEnd):59Z&fields=ClientASN,ClientCountry,ClientDeviceType,ClientIP,ClientIPClass,ClientRequestUserAgent,ClientSSLCipher,ClientSSLProtocol,ClientSrcPort,ClientRequestURI,OriginResponseStatus,ClientRequestReferer,ClientRequestHost,EdgeStartTimestamp,EdgeResponseStatus&timestamps=rfc3339"

    # Enforce TLS1.2 (Cloudflare requires this)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Grab the respective hour from the API
    $headers = Set-HTTPHeaders
    $response = Invoke-WebRequest -Uri "https://api.cloudflare.com/client/v4/zones/$($zone)/logs/received?start=$($year)-$($month)-$($date)T$($getHour):00:00Z&end=$($year)-$($month)-$($date)T$($getHour):$($minuteEnd):59Z&fields=ClientASN,ClientCountry,ClientDeviceType,ClientIP,ClientIPClass,ClientRequestUserAgent,ClientSSLCipher,ClientSSLProtocol,ClientSrcPort,ClientRequestURI,OriginResponseStatus,ClientRequestReferer,ClientRequestHost,EdgeStartTimestamp,EdgeResponseStatus&timestamps=rfc3339" -Headers $headers

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
            $ClientIP = $CSVData.ClientIP -Replace ',', ''
            $ClientIPClass = $CSVData.ClientIPClass -Replace ',', ''
            $ClientCountry = $CSVData.ClientCountry -Replace ',', ''
            $ClientDeviceType = $CSVData.ClientDeviceType -Replace ',', ''
            $ClientSSLCipher = $CSVData.ClientSSLCipher -Replace ',', ''
            $ClientSSLProtocol = $CSVData.ClientSSLProtocol -Replace ',', ''
            $ClientSrcPort = $CSVData.ClientSrcPort -Replace ',', ''
            $ClientRequestURI = $CSVData.ClientRequestURI -Replace ',', ''
            $OriginResponseStatus = $CSVData.OriginResponseStatus -Replace ',', ''
            $ClientRequestReferer = $CSVData.ClientRequestReferer -Replace ',', ''
            $ClientRequestHost = $CSVData.ClientRequestHost -Replace ',', ''
            $EdgeStartTimestamp = $CSVData.EdgeStartTimestamp -Replace ',', ''
            $EdgeResponseStatus = $CSVData.EdgeResponseStatus -Replace ',', ''
        
            # Define what a new line looks like by setting the column headers
            $newLine = "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14}" -f $EdgeStartTimestamp, $ClientASN, $ClientIP, $ClientIPClass, $ClientCountry, $ClientDeviceType, $ClientRequestUserAgent, $ClientSSLCipher, $ClientSSLProtocol, $ClientSrcPort, $EdgeResponseStatus, $OriginResponseStatus, $ClientRequestReferer, $ClientRequestHost, $ClientRequestURI
        
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
}

Write-Host "Complete."
Write-Host
