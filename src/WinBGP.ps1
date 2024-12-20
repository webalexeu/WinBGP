###############################################################################
#                                                                             #
#   Name            WinBGP-CLI                                                #
#                                                                             #
#   Description     WinBGP CLI to manage WinBGP engine                        #
#                                                                             #
#   Notes           Pipe control is based on JFLarvoire service example       #
#                   (https://github.com/JFLarvoire/SysToolsLib)               #
#                                                                             #
#                                                                             #
#   Copyright       (c) 2024 Alexandre JARDON | Webalex System.               #
#                   All rights reserved.'                                     #
#   LicenseUri      https://github.com/webalexeu/winbgp/blob/master/LICENSE   #
#   ProjectUri      https://github.com/webalexeu/winbgp                       #
#                                                                             #
###############################################################################

#Requires -version 5.1

<#
  .SYNOPSIS
    WinBGP CLI local management.

  .DESCRIPTION
    This script manage locally WinBGP.

  .PARAMETER Start
    Start the service.

  .PARAMETER Stop
    Stop the service.

  .PARAMETER Restart
    Stop then restart the service.

  .PARAMETER Status
    Get the current service status: Not installed / Stopped / Running

  .PARAMETER Control
    Send a control message to the service thread.

  .PARAMETER Version
    Display this script version and exit.

  .EXAMPLE
    # Setup the service and run it for the first time
    C:\PS>.\PSService.ps1 -Status
    Not installed
    C:\PS>.\PSService.ps1 -Setup
    C:\PS># At this stage, a copy of PSService.ps1 is present in the path
    C:\PS>PSService -Status
    Stopped
    C:\PS>PSService -Start
    C:\PS>PSService -Status
    Running
    C:\PS># Load the log file in Notepad.exe for review
    C:\PS>notepad ${ENV:windir}\Logs\PSService.log

  .EXAMPLE
    # Stop the service and uninstall it.
    C:\PS>PSService -Stop
    C:\PS>PSService -Status
    Stopped
    C:\PS>PSService -Remove
    C:\PS># At this stage, no copy of PSService.ps1 is present in the path anymore
    C:\PS>.\PSService.ps1 -Status
    Not installed

  .EXAMPLE
    # Configure the service to run as a different user
    C:\PS>$cred = Get-Credential -UserName LAB\Assistant
    C:\PS>.\PSService -Setup -Credential $cred

  .EXAMPLE
    # Send a control message to the service, and verify that it received it.
    C:\PS>PSService -Control Hello
    C:\PS>Notepad C:\Windows\Logs\PSService.log
    # The last lines should contain a trace of the reception of this Hello message
#>
[CmdletBinding(DefaultParameterSetName='BGPStatus')]
Param(
  [Parameter(ParameterSetName='Start', Mandatory=$true)]
  [Switch]$Start,               # Start the service

  [Parameter(ParameterSetName='Stop', Mandatory=$true)]
  [Switch]$Stop,                # Stop the service

  [Parameter(ParameterSetName='Restart', Mandatory=$true)]
  [Switch]$Restart,             # Restart the service

  [Parameter(ParameterSetName='Status', Mandatory=$false)]
  [Switch]$Status = $($PSCmdlet.ParameterSetName -eq 'Status'), # Get the current service status

  [Parameter(ParameterSetName='Control', Mandatory=$true)]
  [String]$Control = $null,     # Control message to send to the service

  [Parameter(ParameterSetName='Reload', Mandatory=$false)]
  [Switch]$Reload = $($PSCmdlet.ParameterSetName -eq 'reload'), # Reload configuration

  [Parameter(ParameterSetName='RouteName', Mandatory=$true)]
  [ArgumentCompleter( {
    param ( $CommandName,
        $ParameterName,
        $WordToComplete,
        $CommandAst,
        $FakeBoundParameters )
    # Dynamically generate routes array
    # TO BE IMPROVED - Set to static temporary
    $configuration=Get-Content 'C:\Program Files\WinBGP\winbgp.json' | ConvertFrom-Json
    [Array] $routes = ($configuration.routes).RouteName
    return $routes
  })]
  [String]$RouteName = $null,     # Select route to control

  [Parameter(ParameterSetName='RouteName', Mandatory=$false)]
  [Switch]$StartMaintenance,     # Control message to send to the service

  [Parameter(ParameterSetName='RouteName', Mandatory=$false)]
  [Switch]$StopMaintenance,     # Control message to send to the service

  [Parameter(ParameterSetName='RouteName', Mandatory=$false)]
  [Switch]$StartRoute,     # Control message to send to the service

  [Parameter(ParameterSetName='RouteName', Mandatory=$false)]
  [Switch]$StopRoute,     # Control message to send to the service

  [Parameter(ParameterSetName='BGPStatus', Mandatory=$false)]
  [Switch]$BGPStatus = $($PSCmdlet.ParameterSetName -eq 'BGPStatus'), # Get the current service status

  [Parameter(ParameterSetName='Config', Mandatory=$false)]
  [Switch]$Config = $($PSCmdlet.ParameterSetName -eq 'Config'), # Get the current configuration

  [Parameter(ParameterSetName='Logs', Mandatory=$false)]
  [Switch]$Logs = $($PSCmdlet.ParameterSetName -eq 'Logs'), # Get the last logs

  [Parameter(ParameterSetName='Logs', Mandatory=$false)]
  [Int]$Last = 20, # Define the last logs number

  [Parameter(ParameterSetName='RestartAPI', Mandatory=$false)]
  [Switch]$RestartAPI,     # RestartAPI

  [Parameter(ParameterSetName='Version', Mandatory=$true)]
  [Switch]$Version              # Get this script version
)

# Don't forget to increment version when updating engine
$scriptVersion = '1.0.1'

# This script name, with various levels of details
# Ex: PSService
$scriptFullName = 'C:\Program Files\WinBGP\WinBGP.ps1'      # Ex: C:\Temp\PSService.ps1

# Global settings
$serviceName = "WinBGP"                 # A one-word name used for net start commands
$serviceDisplayName = "WinBGP"
$pipeName = "Service_$serviceName"      # Named pipe name. Used for sending messages to the service task
$installDir = "${ENV:ProgramW6432}\$serviceDisplayName"  # Where to install the service files
$configfile = "$serviceDisplayName.json"
$configdir = "$installDir\$configfile"
$FunctionCliXml="$installDir\$serviceDisplayName.xml" # Used to stored Maintenance variable
$logName = "Application"                # Event Log name (Unrelated to the logFile!)

# If the -Version switch is specified, display the script version and exit.
if ($Version) {
  return $scriptVersion
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Now                                                       #
#                                                                             #
#   Description     Get a string with the current time.                       #
#                                                                             #
#   Notes           The output string is in the ISO 8601 format, except for   #
#                   a space instead of a T between the date and time, to      #
#                   improve the readability.                                  #
#                                                                             #
#   History                                                                   #
#    2015-06-11 JFL Created this routine.                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Now {
  Param (
    [Switch]$ms,        # Append milliseconds
    [Switch]$ns         # Append nanoseconds
  )
  $Date = Get-Date
  $now = ""
  $now += "{0:0000}-{1:00}-{2:00} " -f $Date.Year, $Date.Month, $Date.Day
  $now += "{0:00}:{1:00}:{2:00}" -f $Date.Hour, $Date.Minute, $Date.Second
  $nsSuffix = ""
  if ($ns) {
    if ("$($Date.TimeOfDay)" -match "\.\d\d\d\d\d\d") {
      $now += $matches[0]
      $ms = $false
    } else {
      $ms = $true
      $nsSuffix = "000"
    }
  } 
  if ($ms) {
    $now += ".{0:000}$nsSuffix" -f $Date.MilliSecond
  }
  return $now
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Log                                                       #
#                                                                             #
#   Description     Log a string into the PSService.log file                  #
#                                                                             #
#   Arguments       A string                                                  #
#                                                                             #
#   Notes           Prefixes the string with a timestamp and the user name.   #
#                   (Except if the string is empty: Then output a blank line.)#
#                                                                             #
#   History                                                                   #
#    2016-06-05 JFL Also prepend the Process ID.                              #
#    2016-06-08 JFL Allow outputing blank lines.                              #
#                                                                             #
#-----------------------------------------------------------------------------#

#Logging function
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
          [ValidateSet("Error","Warning","Information")]
          [string]$Level="Information",

          [Parameter(Mandatory=$false)]
          [string]$EventLogName=$logName,

          [Parameter(Mandatory=$false)]
          [string]$EventLogSource=$serviceName,

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

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Send-PipeMessage                                          #
#                                                                             #
#   Description     Send a message to a named pipe                            #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#    2016-05-25 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Send-PipeMessage () {
  Param(
    [Parameter(Mandatory=$true)]
    [String]$PipeName,          # Named pipe name
    [Parameter(Mandatory=$true)]
    [String]$Message            # Message string
  )
  $PipeDir  = [System.IO.Pipes.PipeDirection]::Out
  $PipeOpt  = [System.IO.Pipes.PipeOptions]::Asynchronous

  $pipe = $null # Named pipe stream
  $sw = $null   # Stream Writer
  try {
    $pipe = new-object System.IO.Pipes.NamedPipeClientStream(".", $PipeName, $PipeDir, $PipeOpt)
    $sw = new-object System.IO.StreamWriter($pipe)
    $pipe.Connect(1000)
    if (!$pipe.IsConnected) {
      throw "Failed to connect client to pipe $pipeName"
    }
    $sw.AutoFlush = $true
    $sw.WriteLine($Message)
  } catch {
    Write-Log "Error sending pipe $pipeName message: $_" -Level Error
  } finally {
    if ($sw) {
      $sw.Dispose() # Release resources
      $sw = $null   # Force the PowerShell garbage collector to delete the .net object
    }
    if ($pipe) {
      $pipe.Dispose() # Release resources
      $pipe = $null   # Force the PowerShell garbage collector to delete the .net object
    }
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Test-ConfigurationFile                                    #
#                                                                             #
#   Description     Test WinBGP configuration file                            #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Test-ConfigurationFile()
{
  Param
  (
    [Parameter(Mandatory=$false)]
    $Path=$configdir
  )

  # Json validation
  try {
    $configuration = Get-Content -Path $Path | ConvertFrom-Json
    $validJson = $true
  } catch {
    $validJson = $false
  }

  if ($validJson) {
    $ValidConfig=$true
    # Global
    if ($configuration.global.Interval -isnot [Int32]) {$ValidConfig=$false}
    if ($configuration.global.Timeout -isnot [Int32]) {$ValidConfig=$false}
    if ($configuration.global.Rise -isnot [Int32]) {$ValidConfig=$false}
    if ($configuration.global.Fall -isnot [Int32]) {$ValidConfig=$false}
    if ($configuration.global.Metric -isnot [Int32]) {$ValidConfig=$false}
    if ($configuration.global.Api -isnot [Boolean]) {$ValidConfig=$false}

    # Api (Check only if Api is enabled)
    if ($configuration.global.Api) {
      if ($configuration.api -isnot [array]) {$ValidConfig=$false}
    }

    # Router
    if ([string]::IsNullOrEmpty($configuration.router.BgpIdentifier)) {$ValidConfig=$false}
    if ([string]::IsNullOrEmpty($configuration.router.LocalASN)) {$ValidConfig=$false}

    # Peers
    if ($configuration.peers -is [array]) {
      foreach ($peer in $configuration.peers) {
        if ([string]::IsNullOrEmpty($peer.PeerName)) {$ValidConfig=$false}
        if ([string]::IsNullOrEmpty($peer.LocalIP)) {$ValidConfig=$false}
        if ([string]::IsNullOrEmpty($peer.PeerIP)) {$ValidConfig=$false}
        if ([string]::IsNullOrEmpty($peer.LocalASN)) {$ValidConfig=$false}
        if ([string]::IsNullOrEmpty($peer.PeerASN)) {$ValidConfig=$false}
      }
    } else {
      $ValidConfig=$false
    }

    # Routes
    if ($configuration.routes -is [array]) {
      foreach ($route in $configuration.routes) {
        if ([string]::IsNullOrEmpty($route.RouteName)) {$ValidConfig=$false}
        if ([string]::IsNullOrEmpty($route.Network)) {$ValidConfig=$false}
        if ([string]::IsNullOrEmpty($route.Interface)) {$ValidConfig=$false}
        if ($route.DynamicIpSetup -isnot [Boolean]) {$ValidConfig=$false}
        if ($route.WithdrawOnDown -isnot [Boolean]) {$ValidConfig=$false}
        # Only if WithdrawOnDown is enabled
        if ($route.WithdrawOnDown) {
          if ([string]::IsNullOrEmpty($route.WithdrawOnDownCheck)) {$ValidConfig=$false}
        }
        if ([string]::IsNullOrEmpty($route.NextHop)) {$ValidConfig=$false}
        # Community
        if ($route.Community -is [array]) {
          # Parsing all Community
          foreach ($community in $route.Community) {
            if ([string]::IsNullOrEmpty($community)) {$ValidConfig=$false}
          }
        } else {
          $ValidConfig=$false
        }
      }
    } else {
      $ValidConfig=$false
    }
  }

  # If Json type and content are valid
  if (($validJson) -and ($ValidConfig)) {
    return $true
  } else {
    return $false
  }
}


#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Main                                                      #
#                                                                             #
#   Description     Execute the specified actions                             #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#

# Identify the user name. We use that for logging.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserName = $identity.Name # Ex: "NT AUTHORITY\SYSTEM" or "Domain\Administrator"

# Workaround for PowerShell v2 bug: $PSCmdlet Not yet defined in Param() block
$Status = ($PSCmdlet.ParameterSetName -eq 'Status')

if ($Start) {                   # The user tells us to start the service
  Write-Verbose "Starting service $serviceName"
  Write-Log -Message "Starting service $serviceName"
  Start-Service $serviceName # Ask Service Control Manager to start it
  return
}

if ($Stop) {                    # The user tells us to stop the service
  Write-Verbose "Stopping service $serviceName"
  Write-Log -Message "Stopping service $serviceName"
  Stop-Service $serviceName # Ask Service Control Manager to stop it
  return
}

if ($Restart) {                 # Restart the service
  & $scriptFullName -Stop
  & $scriptFullName -Start
  return
}

if ($Status) {                  # Get the current service status
  $spid = $null
  $processes = @(Get-WmiObject Win32_Process -filter "Name = 'powershell.exe'" | Where-Object {
    $_.CommandLine -match ".*$scriptCopyCname.*-Service"
  })
  foreach ($process in $processes) { # There should be just one, but be prepared for surprises.
    $spid = $process.ProcessId
    Write-Verbose "$serviceName Process ID = $spid"
  }
  # if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\services\$serviceName") {}
  try {
    $pss = Get-Service $serviceName -ea stop # Will error-out if not installed
  } catch {
    "Not Installed"
    return
  }
  $pss.Status
  if (($pss.Status -eq "Running") -and (!$spid)) { # This happened during the debugging phase
    Write-Error "The Service Control Manager thinks $serviceName is started, but $serviceName.ps1 -Service is not running."
    exit 1
  }
  return
}

if ($Control) {                 # Send a control message to the service
  Send-PipeMessage $pipeName $control
}

#Reload control
if ($Reload) {
  $control='reload'
  Send-PipeMessage $pipeName $control

  # If Json is valid, reloading
  if (Test-ConfigurationFile) {
    return 'Success'
  } else {
    return "Configuration file '$($configdir)' is not valid"
  }
}

# Restart API
if ($RestartAPI) {
  $control='restart api'
  Send-PipeMessage $pipeName $control
  # Output message to be improved
  return 'Success'
}

# Start/stop control or Maintenance control
if ($StartRoute -or $StopRoute -or $StartMaintenance -or $StopMaintenance) {
  # Logging
  Write-Log "Operation for route '$RouteName' triggered by '$currentUserName'"
  # Read configuration
  $configuration = Get-Content -Path $configdir | ConvertFrom-Json
  $routeCheck=$null
  $routeCheck=$configuration.routes | Where-Object {$_.RouteName -eq $RouteName}
  # Start/stop control
  if ($StartRoute -or $StopRoute) {
    # START
    if ($StartRoute) {
      $control="route $RouteName start"
    }
    # STOP
    if ($StopRoute) {
        $control="route $RouteName stop" 
    }
  }
  # Maintenance control
  if ($StartMaintenance -or $StopMaintenance) {
    # START
    if ($StartMaintenance) {
      $control="maintenance $RouteName start"
    }
    # STOP
    if ($StopMaintenance) {      
      $control="maintenance $RouteName stop"
    }
  }
  if($routeCheck) {
    $PipeStatus=$null
    # Performing Action
    try {
      Send-PipeMessage $pipeName $control
    }
    catch {
      $PipeStatus=($_).ToString()
    } 
    if ($PipeStatus -like "*Pipe hasn't been connected yet*") {
      return "WinBGP not ready"
    } else {
      # TO BE IMPROVED to get status
      return "Success"
    }
  } else {
    # Logging
    Write-Log "Received control message: $control"
    Write-Log "Control return: Route '$RouteName' not found" -Level Warning
    return "Route '$RouteName' not found"
  }
}

# Get the current BGP status
if ($BGPStatus) {
  # Read configuration
  $configuration = Get-Content -Path $configdir | ConvertFrom-Json
  # Read maintenance
  #If there is a maintenance, import it
  if(Test-Path -Path $FunctionCliXml) {
    #Import variable
    $maintenance=Import-CliXml -Path $FunctionCliXml
  } else {
    #Otherwise, initialize variable
    $maintenance = @{}
  }

  # Read BGP routes and policy (To optimize query)
  $BGPRoutes=$null
  $BGPPolicies=$null
  try {
    # Use CIM query to improve performance
    $BGPRoutes=(Invoke-CimMethod -ClassName "PS_BgpCustomRoute" -Namespace 'ROOT\Microsoft\Windows\RemoteAccess' -MethodName Get).cmdletoutput.Network
    $BGPPolicies=(Invoke-CimMethod -ClassName "PS_BgpRoutingPolicy" -Namespace 'ROOT\Microsoft\Windows\RemoteAccess' -MethodName Get).cmdletoutput.PolicyName
  }
  catch {
  }

  # Read IP Addresses (To optimize query)
  $IPAddresses=(Get-NetIPAddress -AddressFamily IPv4).IPAddress

  #Parse all routes
  $Routes=@()
  ForEach ($route in $configuration.routes) {
    $RouteStatus=$null
    $RouteStatusDetailled=$null
    # Check if route is in maintenance mode
    if ($maintenance.($route.RouteName)) {
      $RouteStatus='maintenance'
    # Check if route is up (Only if BGP service is configured)
    } else {
      if ($BGPRoutes -contains "$($route.Network)") {
        # Check route policy
        if ($BGPPolicies -contains "$($route.RouteName)") {
          # Check IP
          if ($route.DynamicIpSetup) {
            if ($IPAddresses -contains "$($route.Network.split('/')[0])") {
              $RouteStatus='up'
            } else {
              $RouteStatus='warning'
              $RouteStatusDetailled='IP Address not mounted'
            } 
          } else {
            $RouteStatus='up'
          }
        } else {
          $RouteStatus='warning'
          $RouteStatusDetailled='No routing policy defined'
        }
      # Route down
      } else {
        # Check IP
        if ($route.DynamicIpSetup) {
          if ($IPAddresses -contains "$($route.Network.split('/')[0])") {
            $RouteStatus='warning'
            $RouteStatusDetailled='IP Address still mounted'
          } else {
            $RouteStatus='down'
          }
        } else {
          $RouteStatus='down'
        }
      }
    }
    $RouteProperties=[PSCustomObject]@{
      Name                 = $route.RouteName;
      Network              = $route.Network;
      Status               = $RouteStatus;
      MaintenanceTimestamp = $maintenance.($route.RouteName);
      RouteStatusDetailled = $RouteStatusDetailled;
    }
    # Add route to array
    $Routes += $RouteProperties
  }
  # Select default properties to display
  $defaultDisplaySet = 'Name','Network','Status','MaintenanceTimestamp'
  $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
  $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
  $Routes | Add-Member MemberSet PSStandardMembers $PSStandardMembers

  return $Routes
}

if ($Config) {
  # If Json is valid, reloading
  if (Test-ConfigurationFile) {
    $configuration = Get-Content -Path $configdir | ConvertFrom-Json
    return $configuration
  } else {
    return "Configuration file '$($configdir)' is not valid"
  }
}

if ($Logs) {
  $EventLogs=Get-EventLog -LogName Application -Source WinBGP -Newest $Last | Select-Object Index,TimeGenerated,EntryType,Message,ReplacementStrings
  $DisplayLogs=@()
  foreach ($log in $EventLogs) {
    if($log.ReplacementStrings -gt 1) {
      $log | Add-Member -MemberType NoteProperty -Name 'RouteName' -Value $log.ReplacementStrings[1]
    }
    $log.PsObject.Members.Remove('ReplacementStrings')
    $DisplayLogs+=$log
  }

  # Select default properties to display
  $defaultDisplaySet = 'TimeGenerated','EntryType','Message','RouteName'
  $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
  $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
  $DisplayLogs | Add-Member MemberSet PSStandardMembers $PSStandardMembers
  
  return $DisplayLogs
}
