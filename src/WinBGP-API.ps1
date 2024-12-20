###############################################################################
#                                                                             #
#   Name            WinBGP-Api                                                #
#                                                                             #
#   Description     WinBGP API engine                                         #
#                                                                             #
#   Notes           Service is based on stevelee http listener example        #
#                   (https://www.powershellgallery.com/packages/HttpListener) #
#                                                                             #
#                                                                             #
#   Copyright       (c) 2024 Alexandre JARDON | Webalex System.               #
#                   All rights reserved.'                                     #
#   LicenseUri      https://github.com/webalexeu/winbgp/blob/master/LICENSE   #
#   ProjectUri      https://github.com/webalexeu/winbgp                       #
#                                                                             #
###############################################################################

#Requires -version 5.1

# Based on 

Param (
    $Configuration=$false
)

$scriptVersion = '1.1.1'

# Create detailled log for WinBGP-API
# New-EventLog –LogName Application –Source 'WinBGP-API' -ErrorAction SilentlyContinue

# Logging function
function Write-Log {
    <#
    .Synopsis
       Write-Log writes a message to a specified log file with the current time stamp.
    .DESCRIPTION
       The Write-Log function is designed to add logging capability to other scripts.
       In addition to writing output and/or verbose you can write to a log file for
       later debugging.
    .NOTES
       Created by: Jason Wasser @wasserja
       Modified: 11/24/2015 09:30:19 AM  
    
       Changelog:
        * Code simplification and clarification - thanks to @juneb_get_help
        * Added documentation.
        * Renamed LogPath parameter to Path to keep it standard - thanks to @JeffHicks
        * Revised the Force switch to work as it should - thanks to @JeffHicks
    
       To Do:
        * Add error handling if trying to create a log file in a inaccessible location.
        * Add ability to write $Message to $Verbose or $Error pipelines to eliminate
          duplicates.
    .PARAMETER Message
       Message is the content that you wish to add to the log file. 
    .PARAMETER Path
       The path to the log file to which you would like to write. By default the function will 
       create the path and file if it does not exist. 
    .PARAMETER Level
       Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)
    .PARAMETER NoClobber
       Use NoClobber if you do not wish to overwrite an existing file.
    .EXAMPLE
       Write-Log -Message 'Log message' 
       Writes the message to c:\Logs\PowerShellLog.log.
    .EXAMPLE
       Write-Log -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
       Writes the content to the specified log file and creates the path and file specified. 
    .EXAMPLE
       Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
       Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
    .LINK
       https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0
    #>
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()]
            [Alias("LogContent")]
            [string]$Message,
    
            [Parameter(Mandatory=$false)]
            [Alias('LogPath')]
            [string]$Path,
            
            [Parameter(Mandatory=$false)]
            [ValidateSet("Error","Warning","Information")]
            [string]$Level="Information",
  
            [Parameter(Mandatory=$false)]
            [string]$EventLogName='Application',
  
            [Parameter(Mandatory=$false)]
            [string]$EventLogSource='WinBGP',
  
            [Parameter(Mandatory=$false)]
            [string]$EventLogId=1006,
  
            [Parameter(Mandatory=$false)]
            [string]$EventLogCategory=0,
  
            [Parameter(Mandatory=$false)]
            [Array]$AdditionalFields=$null,
  
            [Parameter(Mandatory=$false)]
            [switch]$NoClobber
        )
    
        Begin
        {
        }
        Process
        {
          #Create Log file only if Path is defined
          if ($Path) {
            # If the file already exists and NoClobber was specified, do not write to the log.
            if ((Test-Path $Path) -AND $NoClobber) {
                Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
                Return
                }
    
            # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
            elseif (!(Test-Path $Path)) {
                Write-Verbose "Creating $Path."
                $NewLogFile = New-Item $Path -Force -ItemType File
                }
    
            else {
                # Nothing to see here yet.
                }
    
            # Format Date for our Log File
            $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            # Write log entry to $Path
            "$FormattedDate $Level $Message" | Out-File -FilePath $Path -Append
          }
          # Manage AdditionalFields (Not by default with PowerShell function)
          if ($AdditionalFields) {
            $EventInstance = [System.Diagnostics.EventInstance]::new($EventLogId, $EventLogCategory, $Level)
            $NewEvent = [System.Diagnostics.EventLog]::new()
            $NewEvent.Log = $EventLogName
            $NewEvent.Source = $EventLogSource
            [Array] $JoinedMessage = @(
            $Message
            $AdditionalFields | ForEach-Object { $_ }
            )
            $NewEvent.WriteEvent($EventInstance, $JoinedMessage)
          } else {
            #Write log to event viewer (Enabled by default)
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId $EventLogId -EntryType $Level -Category $EventLogCategory -Message "$Message"
          }
        }
        End
        {
        }
}

# Prometheus function
function New-PrometheusMetricDescriptor(
    [Parameter(Mandatory = $true)][String] $Name,
    [Parameter(Mandatory = $true)][String] $Type,
    [Parameter(Mandatory = $true)][String] $Help,
    [string[]] $Labels
) {
    # Verification
    if ($Name -notmatch "^[a-zA-Z_][a-zA-Z0-9_]*$") {
        throw "Prometheus Descriptor Name '$($Name)' not valid"
    }
    foreach ($Label in $Labels) {
        if ($Label -notmatch "^[a-zA-Z_][a-zA-Z0-9_]*$") {
            throw "Prometheus Descriptor Label Name '$($Label)' not valid"
        }
    }

    # return object
    return [PSCustomObject]@{
        PSTypeName = 'PrometheusMetricDescriptor'
        Name       = $Name
        Help       = $Help -replace "[\r\n]+", " "  # Strip out new lines
        Type       = $Type
        Labels     = $Labels
    }
}

function New-PrometheusMetric (
    [Parameter(Mandatory = $true)][PSTypeName('PrometheusMetricDescriptor')] $PrometheusMetricDescriptor,
    [Parameter(Mandatory = $true)][float] $Value,
    [string[]] $Labels
) {
    # Verification
    if (($PrometheusMetricDescriptor.Labels).Count -ne $Labels.Count) {
        throw "Metric labels are not matching the labels specified in the PrometheusMetricDescriptor provided"
    }
    # return object
    return [PSCustomObject]@{
        PSTypeName = 'PrometheusMetric'
        Name        = $PrometheusMetricDescriptor.Name
        PrometheusMetricDescriptor  = $PrometheusMetricDescriptor
        Value       = $Value
        Labels      = $Labels
    }
}

function Export-PrometheusMetrics (
    [PSTypeName('PrometheusMetric')][object[]] $Metrics
) {
    $Lines = [System.Collections.Generic.List[String]]::new()
    $LastDescriptor = $null
    # Parse all metrics
    foreach ($metric in $Metrics) {
        if ($metric.PrometheusMetricDescriptor -ne $LastDescriptor) {
            # Populate last descriptor
            $LastDescriptor = $metric.PrometheusMetricDescriptor
            $Lines.Add("# HELP $($LastDescriptor.Name) $($LastDescriptor.Help)")
            $Lines.Add("# TYPE $($LastDescriptor.Name) $($LastDescriptor.Type)")
        }

        $FinalLabels = [System.Collections.Generic.List[String]]::new()
        if (($metric.PrometheusMetricDescriptor.Labels).Count -gt 0) {
            for ($i = 0; $i -lt ($metric.PrometheusMetricDescriptor.Labels).Count; $i++) {
                $label = $metric.PrometheusMetricDescriptor.Labels[$i]
                $value = ($metric.Labels[$i]).Replace("\", "\\").Replace("""", "\""").Replace("`n", "\n")
                $FinalLabels.Add("$($label)=`"$($value)`"")
            }
            $StringLabels = $FinalLabels -join ","
            $StringLabels = "{$StringLabels}"
        } else {
            $StringLabels = ""
        }
        $Lines.Add([String] $metric.Name + $StringLabels + " " + $metric.Value)
    }
    return $Lines -join "`n"
}

# Only processing if there is configuration
if ($Configuration) {
    # Creating Prefixes variable
    $ListenerPrefixes=@()
    # Default Authentication Method/Group
    $AuthenticationMethod='Anonymous'
    $AuthenticationGroup='Administrators'
    # Parsing all URIs
    foreach ($item in $Configuration) {
        [String] $Uri = $item.Uri
        [System.Net.AuthenticationSchemes] $AuthMethod = $item.AuthenticationMethod
        if ($AuthMethod -eq 'Negotiate') {
            [String] $AuthGroup = $item.AuthenticationGroup
        }
    
        # Splitting Uri
        [String]$Protocol = $Uri.Split('://')[0]
        [String]$IP = $Uri.Split('://')[3]
        [String]$Port = $Uri.Split('://')[4]

        # TO IMPROVE
        if ($IP -ne '127.0.0.1') {
            $AuthenticationMethod=$AuthMethod
            $AuthenticationGroup=$AuthGroup
        }
    
        # Manage certificate
        $SSLConfigurationError=$false
        if ($Protocol -eq 'https') {
            # Populate variable
            [String] $CertificateThumbprint = $item.CertificateThumbprint
            # Managing cert on port
            netsh http delete sslcert ipport="$($IP):$($Port)" | Out-Null
            netsh http add sslcert ipport="$($IP):$($Port)" certhash="$CertificateThumbprint" appid='{00112233-4455-6677-8899-AABBCCDDEEFF}' | Out-Null
            # Parsing netsh output to checck SSL configuration
            $netshOutput=netsh http show sslcert ipport="$($IP):$($Port)" | Where-Object {($_.Split("`r`n")) -like '*IP:port*'}
            if ($netshOutput -ne "    IP:port                      : $($IP):$($Port)") {
                Write-Log -Message "API failed - SSL configuration error" -Level Error
                $SSLConfigurationError=$true
            }
        }

        # If no SSL configuration error, checking
        if ($SSLConfigurationError -ne $true)  {
            # Checking if listening port is available
            if (Get-NetTCPConnection -LocalAddress $IP -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
                Write-Log -Message "Uri failed - Port '$($Port)' on IP '$($IP)' is already in use" -Level Error
            } else {
                # Adding / on Uri
                $ListenerPrefixes+="$($Uri)/"
            }
        }
    }

    # If there is listener to start
    if ($ListenerPrefixes) {
        $listener = New-Object System.Net.HttpListener
        # Adding listener
        foreach ($ListenerPrefixe in $ListenerPrefixes) {
            $listener.Prefixes.Add($ListenerPrefixe)
        }
        # Used previously when only one scheme was used
        #$listener.AuthenticationSchemes = $AuthMethod
        # Dynamic authentication schemes (TO IMPROVE)
        $Listener.AuthenticationSchemeSelectorDelegate = { param($request)
            # If local means Uri IP is 127.0.0.1
            if ($request.IsLocal) {
                # If local, we don't support authentication for now (TO IMPROVE)
                return [System.Net.AuthenticationSchemes]::Anonymous
            } else {
                # TO IMPROVE
                switch ( $AuthenticationMethod) {
                    'Negotiate' { $AuthenticationSchemes=[System.Net.AuthenticationSchemes]::IntegratedWindowsAuthentication }
                    'Anonymous' { $AuthenticationSchemes=[System.Net.AuthenticationSchemes]::Anonymous }
                }
                # Set default to anonymous
                return $AuthenticationSchemes
            }
        }
        # Starting listerner
        $listener.Start()
        # Output listeners
        foreach ($ListenerPrefixe in $ListenerPrefixes) {
            [String]$Protocol = $ListenerPrefixe.Split('://')[0]
            [String]$IP = $ListenerPrefixe.Split('://')[3]
            [String]$Port = $ListenerPrefixe.Split('://')[4]
            Write-Log -Message "API started - Listening on '$($IP):$($Port)' (Protocol: $Protocol)"
        }
        
        while ($listener.IsListening) {
            # Default return
            $statusCode = [System.Net.HttpStatusCode]::OK
            $commandOutput = [string]::Empty
            $outputHeader = @{}
            $context = $listener.GetContext()
            $request = $context.Request
            [string]$RequestHost=$request.RemoteEndPoint
            $RequestHost=($RequestHost).split(':')[0]
            # Manage authentication
            $Authenticated=$false
            if ($AuthenticationMethod -eq 'Negotiate') {
                if ($request.IsAuthenticated) {
                    $RequestUser=$context.User.Identity.Name
                    if ($($context.User.IsInRole($AuthenticationGroup))) {
                        $Authenticated=$true
                    } else {
                        $statusCode = [System.Net.HttpStatusCode]::Forbidden
                    }
                } else {
                    $statusCode = [System.Net.HttpStatusCode]::Unauthorized
                }
            } elseif ($AuthenticationMethod -eq 'Anonymous') {
                $Authenticated=$true
                $RequestUser='Anonymous'
            }
            
            # If local, we don't support authentication for now (TO IMPROVE)
            if ($request.IsLocal -or $Authenticated) {
                # Log every api request
                # [string]$FullRequest = $request | Format-List * | Out-String
                # Write-Log "API request received: $FullRequest" -EventLogSource 'WinBGP-API'
                $FullPath=($request.RawUrl).substring(1)
                $Path=$FullPath.Split('?')[0]
                switch ($request.HttpMethod) {
                    'GET' {
                        if ($FullPath -eq 'api') {
                            $commandOutput = ConvertTo-Json -InputObject @{'message'='WinBGP API running'}
                            $statusCode = [System.Net.HttpStatusCode]::OK
                        } elseif ($FullPath -like 'api/*') {
                            $Path=$Path.replace('api/','')
                            $shortPath=$Path.Split('/')[0]
                            switch ($shortPath) {
                                'config' {
                                    if (($Path -eq 'config') -or ($Path -eq 'config/')) {
                                        $commandOutput = WinBGP -Config | ConvertTo-JSON
                                        $outputHeader.Add('Content-Type', 'application/json')
                                        $statusCode = [System.Net.HttpStatusCode]::OK
                                    } else {
                                        $SubConfig=$Path.Split('/')[1]
                                        $commandOutput = (WinBGP -Config).$SubConfig
                                        if ($commandOutput) {
                                            $commandOutput = $commandOutput | ConvertTo-JSON
                                            $outputHeader.Add('Content-Type', 'application/json')
                                            $statusCode = [System.Net.HttpStatusCode]::OK
                                        } else {
                                            $statusCode = [System.Net.HttpStatusCode]::NotFound
                                        }
                                    }
                                }
                                'logs' {
                                    $Last = $request.QueryString.Item("Last")
                                    if (!($Last)) { $Last = 10 }
                                    $commandOutput = WinBGP -Logs -Last $Last | Select-Object Index,TimeGenerated,@{Label='EntryType';Expression={($_.EntryType).ToString()}},Message,RouteName | ConvertTo-JSON
                                    $outputHeader.Add('Content-Type', 'application/json')
                                    $statusCode = [System.Net.HttpStatusCode]::OK
                                }
                                'peers' {
                                    if (($Path -eq 'peers') -or ($Path -eq 'peers/'))  {     
                                        $commandOutput = ConvertTo-Json -InputObject @(Get-BgpPeer | Select-Object PeerName,LocalIPAddress,LocalASN,PeerIPAddress,PeerASN,@{Label='ConnectivityStatus';Expression={$_.ConnectivityStatus.ToString()}}) #Using @() as inputobject to always return an array                                     
                                        $outputHeader.Add('Content-Type', 'application/json')
                                        $statusCode = [System.Net.HttpStatusCode]::OK
                                    } else {
                                        $PeerName=$Path.Split('/')[1]
                                        $commandOutput = Get-BgpPeer | Where-Object {$_.PeerName -eq $PeerName} | Select-Object PeerName,LocalIPAddress,PeerIPAddress,PeerASN,@{Label='ConnectivityStatus';Expression={$_.ConnectivityStatus.ToString()}}
                                        if ($commandOutput) {
                                            $commandOutput = $commandOutput | ConvertTo-JSON
                                            $outputHeader.Add('Content-Type', 'application/json')
                                            $statusCode = [System.Net.HttpStatusCode]::OK
                                        } else {
                                            $statusCode = [System.Net.HttpStatusCode]::NotFound
                                        }
                                    }
                                }
                                'router' {
                                    $commandOutput = Get-BgpRouter | Select-Object BgpIdentifier,LocalASN,PeerName,PolicyName | ConvertTo-JSON
                                    $statusCode = [System.Net.HttpStatusCode]::OK
                                }
                                'routes' {
                                    if (($Path -eq 'routes') -or ($Path -eq 'routes/')) {
                                        $commandOutput = ConvertTo-Json -InputObject @(WinBGP | Select-Object Name,Network,Status,@{Label='MaintenanceTimestamp';Expression={($_.MaintenanceTimestamp).ToString("yyyy-MM-ddTHH:mm:ss.fffK")}}) #Using @() as inputobject to always return an array
                                        $outputHeader.Add('Content-Type', 'application/json')
                                        $statusCode = [System.Net.HttpStatusCode]::OK
                                    } else {
                                        $RouteName=$Path.Split('/')[1]
                                        $commandOutput = WinBGP | Where-Object {$_.Name -eq $RouteName} | Select-Object Name,Network,Status,@{Label='MaintenanceTimestamp';Expression={($_.MaintenanceTimestamp).ToString("yyyy-MM-ddTHH:mm:ss.fffK")}}
                                        if ($commandOutput) {
                                            $commandOutput = $commandOutput | ConvertTo-JSON
                                            $outputHeader.Add('Content-Type', 'application/json')
                                            $statusCode = [System.Net.HttpStatusCode]::OK
                                        } else {
                                            $statusCode = [System.Net.HttpStatusCode]::NotFound
                                        }
                                    }
                                }
                                'statistics' {
                                    $commandOutput=(Invoke-CimMethod -ClassName "PS_BgpStatistics" -Namespace 'ROOT\Microsoft\Windows\RemoteAccess' -MethodName Get -OperationTimeoutSec 5).cmdletoutput | Select-Object PeerName,TcpConnectionEstablished,TcpConnectionClosed,@{Label='OpenMessage';Expression={$_.OpenMessage.CimInstanceProperties | Select-Object Name,Value}},@{Label='NotificationMessage';Expression={$_.NotificationMessage.CimInstanceProperties | Select-Object Name,Value}},@{Label='KeepAliveMessage';Expression={$_.KeepAliveMessage.CimInstanceProperties | Select-Object Name,Value}},@{Label='RouteRefreshMessage';Expression={$_.RouteRefreshMessage.CimInstanceProperties | Select-Object Name,Value}},@{Label='UpdateMessage';Expression={$_.UpdateMessage.CimInstanceProperties | Select-Object Name,Value}},@{Label='IPv4Route';Expression={$_.IPv4Route.CimInstanceProperties | Select-Object Name,Value}},@{Label='IPv6Route';Expression={$_.IPv6Route.CimInstanceProperties | Select-Object Name,Value}} | ConvertTo-JSON
                                    $outputHeader.Add('Content-Type', 'application/json')
                                    $statusCode = [System.Net.HttpStatusCode]::OK
                                }
                                'status' {
                                    [string]$status = WinBGP -Status
                                    $commandOutput = ConvertTo-Json -InputObject @{'service'=$status}
                                    $outputHeader.Add('Content-Type', 'application/json')
                                    $statusCode = [System.Net.HttpStatusCode]::OK
                                }
                                'version' {
                                    $commandOutput = WinBGP -Version | ConvertTo-JSON
                                    $outputHeader.Add('Content-Type', 'application/json')
                                    $statusCode = [System.Net.HttpStatusCode]::OK
                                }
                                Default {
                                    $statusCode = [System.Net.HttpStatusCode]::NotImplemented
                                }
                            }
                        } elseif ($FullPath -eq 'metrics') {
                            # Define WinBGP Prometheus metrics
                            $WinBGP_metrics=@()
                            
                            # WinBGP peer status
                            $state_peerDescriptor=New-PrometheusMetricDescriptor -Name winbgp_state_peer -Type gauge -Help 'WinBGP Peers status' -Labels local_asn,local_ip,name,peer_asn,peer_ip,state
                            $peerStatus=@('connected','connecting','stopped')
                            # Try/catch to detect if BGP is configured properly
                            $BgpStatus=$null
                            try {
                                $peersCurrentStatus=Get-BgpPeer -ErrorAction SilentlyContinue | Select-Object PeerName,LocalIPAddress,LocalASN,PeerIPAddress,PeerASN,@{Label='ConnectivityStatus';Expression={$_.ConnectivityStatus.ToString()}}
                            }
                            catch {
                              #If BGP Router (Local) is not configured, catch it
                              $BgpStatus=($_).ToString()
                            }
                            if ($BgpStatus -eq 'BGP is not configured.') {
                                $peersCurrentStatus=$null
                            }
                            # Parse all peers and generate metric
                            foreach ($peerCurrentStatus in $peersCurrentStatus) {
                                foreach ($status in $peerStatus) {
                                    $WinBGP_metrics+=New-PrometheusMetric -PrometheusMetricDescriptor $state_peerDescriptor -Value $(if ($status -eq $peerCurrentStatus.ConnectivityStatus) { 1 } else { 0 }) -Labels $peerCurrentStatus.LocalASN,$peerCurrentStatus.LocalIPAddress,$peerCurrentStatus.PeerName,$peerCurrentStatus.PeerASN,$peerCurrentStatus.PeerIPAddress,$status
                                }
                            }

                            # WinBGP route status
                            $state_routeDescriptor=New-PrometheusMetricDescriptor -Name winbgp_state_route -Type gauge -Help 'WinBGP routes status' -Labels family,maintenance_timestamp,name,network,state
                            $routeStatus=@('down','maintenance','up','warning')
                            # Silently continue as WinBGP is generating errors when BGP is not configured (TO REVIEW)
                            $routesCurrentStatus=(WinBGP -ErrorAction SilentlyContinue | Select-Object Name,Network,Status,@{Label='MaintenanceTimestamp';Expression={($_.MaintenanceTimestamp).ToString("yyyy-MM-ddTHH:mm:ss.fffK")}})
                            foreach ($routeCurrentStatus in $routesCurrentStatus) {
                                foreach ($status in $routeStatus) {
                                    $WinBGP_metrics+=New-PrometheusMetric -PrometheusMetricDescriptor $state_routeDescriptor -Value $(if ($status -eq $routeCurrentStatus.Status) { 1 } else { 0 }) -Labels 'ipv4',$routeCurrentStatus.MaintenanceTimestamp,$routeCurrentStatus.Name,$routeCurrentStatus.Network,$status
                                }
                            }

                            # Return output
                            $commandOutput = Export-PrometheusMetrics -Metrics $WinBGP_metrics
                            
                            # Add header
                            $outputHeader.Add('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
                            $statusCode = [System.Net.HttpStatusCode]::OK
                        } else {
                            $statusCode = [System.Net.HttpStatusCode]::NotImplemented
                        }
                    }
                    'POST' {
                        if ($FullPath -like 'api/*') {
                            $RouteName = $request.QueryString.Item("RouteName")
                            $Path=$Path.replace('api/','')
                            Write-Log "API received POST request '$Path' from '$RequestUser' - Source IP: '$RequestHost'" -AdditionalFields $RouteName
                            switch ($Path) {
                                'Reload' { 
                                    [string]$ActionOutput=WinBGP -Reload
                                    $commandOutput = ConvertTo-Json -InputObject @{'output'=$ActionOutput}
                                    $outputHeader.Add('Content-Type', 'application/json')
                                }
                                'StartMaintenance' {
                                    [string]$ActionOutput=WinBGP -RouteName "$RouteName" -StartMaintenance
                                    $commandOutput = ConvertTo-Json -InputObject @{'output'=$ActionOutput}
                                    $outputHeader.Add('Content-Type', 'application/json')
                                }
                                'StartRoute' { 
                                    [string]$ActionOutput=WinBGP -RouteName "$RouteName" -StartRoute
                                    $commandOutput = ConvertTo-Json -InputObject @{'output'=$ActionOutput}
                                    $outputHeader.Add('Content-Type', 'application/json')
                                }
                                'StopMaintenance' { 
                                    [string]$ActionOutput=WinBGP -RouteName "$RouteName" -StopMaintenance
                                    $commandOutput = ConvertTo-Json -InputObject @{'output'=$ActionOutput}
                                    $outputHeader.Add('Content-Type', 'application/json')
                                }
                                'StopRoute' { 
                                    [string]$ActionOutput=WinBGP -RouteName "$RouteName" -StopRoute
                                    $commandOutput = ConvertTo-Json -InputObject @{'output'=$ActionOutput}
                                    $outputHeader.Add('Content-Type', 'application/json')
                                }
                                Default {
                                    $statusCode = [System.Net.HttpStatusCode]::NotImplemented
                                }
                            }
                            switch ($commandOutput.output) {
                                'Success' { $statusCode = [System.Net.HttpStatusCode]::OK }
                                'WinBGP not ready' { $statusCode = [System.Net.HttpStatusCode]::InternalServerError }
                            }
                        } else {
                            $statusCode = [System.Net.HttpStatusCode]::NotImplemented
                        }
                    }
                    Default {
                        $statusCode = [System.Net.HttpStatusCode]::NotImplemented
                    }
                }
            }
            $response = $context.Response
            $response.StatusCode = $statusCode
            foreach ($header in $outputHeader.Keys)
            {
                foreach ($headerValue in $outputHeader.$header)
                {
                    $response.Headers.Add($header, $headerValue)
                }
            }
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($commandOutput)
            $response.ContentLength64 = $buffer.Length
            $output = $response.OutputStream
            $output.Write($buffer,0,$buffer.Length)
            $output.Close()
        }
        $listener.Stop()
    } else {
        Write-Log -Message "API failed - No Uri listener available" -Level Error
    }
} else {
    $OutputVersion=@{
        'Version'=$scriptVersion
    }
    return $OutputVersion
}
