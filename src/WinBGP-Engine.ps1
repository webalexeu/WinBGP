###############################################################################
#                                                                             #
#   Name            WinBGP-Engine                                             #
#                                                                             #
#   Description     WinBGP Engine (Called by the service)                     #
#                                                                             #
#   Notes           Service is based on JFLarvoire service example            #
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

[CmdletBinding(DefaultParameterSetName='Version')]
Param(
  [Parameter(ParameterSetName='Start', Mandatory=$true)]
  [Switch]$Start,               # Start the service

  [Parameter(ParameterSetName='Stop', Mandatory=$true)]
  [Switch]$Stop,                # Stop the service

  [Parameter(ParameterSetName='Restart', Mandatory=$true)]
  [Switch]$Restart,             # Restart the service

  [Parameter(ParameterSetName='Status', Mandatory=$false)]
  [Switch]$Status = $($PSCmdlet.ParameterSetName -eq 'Status'), # Get the current service status

  [Parameter(ParameterSetName='Service', Mandatory=$true)]
  [Switch]$Service,               # Run the service (Internal use only)

  [Parameter(ParameterSetName='SCMStart', Mandatory=$true)]
  [Switch]$SCMStart,              # Process SCM Start requests (Internal use only)

  [Parameter(ParameterSetName='SCMResume', Mandatory=$true)]
  [Switch]$SCMResume,             # Process SCM Resume requests (Internal use only)

  [Parameter(ParameterSetName='SCMStop', Mandatory=$true)]
  [Switch]$SCMStop,               # Process SCM Stop requests (Internal use only)

  [Parameter(ParameterSetName='SCMSuspend', Mandatory=$true)]
  [Switch]$SCMSuspend,            # Process SCM Suspend requests (Internal use only)

  [Parameter(ParameterSetName='Control', Mandatory=$true)]
  [String]$Control = $null,     # Control message to send to the service

  [Parameter(ParameterSetName='Version', Mandatory=$true)]
  [Switch]$Version              # Get this script version
)

# Don't forget to increment version when updating engine
$scriptVersion = '1.1.1'


# This script name, with various levels of details
$argv0 = Get-Item $MyInvocation.MyCommand.Definition
$script = $argv0.basename               # Ex: PSService
$scriptName = $argv0.name               # Ex: PSService.ps1
$scriptFullName = $argv0.fullname       # Ex: C:\Temp\PSService.ps1

# Global settings
$serviceName = "WinBGP"                # A one-word name used for net start commands
$serviceDisplayName = "WinBGP"
# To improve (Service name should be rationalized)
$serviceInternalName = "$($serviceName)-Service"
$engineName = "$($serviceName)-Engine"
$ServiceDescription = "The BGP swiss army knife of networking on Windows"
$pipeName = "Service_$serviceName"      # Named pipe name. Used for sending messages to the service task
$installDir = "${ENV:ProgramW6432}\$serviceDisplayName"  # Where to install the service files
$scriptCopy = "$installDir\$scriptName"
$configfile = "$serviceDisplayName.json"
$configdir = "$installDir\$configfile"
$exeName = "$serviceName.exe"
$exeFullName = "$installDir\$exeName"
# Remove file log
#$logDir = "${ENV:programfiles}\WinBGP\Logs"          # Where to log the service messages
#$logFile = "$logDir\$serviceName.log"
$logName = "Application"                # Event Log name (Unrelated to the logFile!)
$FunctionCliXml="$installDir\$serviceDisplayName.xml" # Used to stored Maintenance variable
# Note: The current implementation only supports "classic" (ie. XP-compatble) event logs.
#	To support new style (Vista and later) "Applications and Services Logs" folder trees, it would
#	be necessary to use the new *WinEvent commands instead of the XP-compatible *EventLog commands.
# Gotcha: If you change $logName to "NEWLOGNAME", make sure that the registry key below does not exist:
#         HKLM\System\CurrentControlSet\services\eventlog\Application\NEWLOGNAME
#	  Else, New-EventLog will fail, saying the log NEWLOGNAME is already registered as a source,
#	  even though "Get-WinEvent -ListLog NEWLOGNAME" says this log does not exist!

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

# Remove file log
# Function Log () {
#   Param(
#     [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
#     [String]$string
#   )
#   if (!(Test-Path $logDir)) {
#     New-Item -ItemType directory -Path $logDir | Out-Null
#   }
#   if ($String.length) {
#     # Remove $currentUserName
#     #$string = "$(Now) $pid $currentUserName $string"
#     $string = "$(Now) $pid $string"
#   }
#   $string | Out-File -Encoding ASCII -Append "$logFile"
# }

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Start-PSThread                                            #
#                                                                             #
#   Description     Start a new PowerShell thread                             #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes           Returns a thread description object.                      #
#                   The completion can be tested in $_.Handle.IsCompleted     #
#                   Alternative: Use a thread completion event.               #
#                                                                             #
#   References                                                                #
#    https://learn-powershell.net/tag/runspace/                               #
#    https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/
#    http://www.codeproject.com/Tips/895840/Multi-Threaded-PowerShell-Cookbook
#                                                                             #
#   History                                                                   #
#    2016-06-08 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

$PSThreadCount = 0              # Counter of PSThread IDs generated so far
$PSThreadList = @{}             # Existing PSThreads indexed by Id

Function Get-PSThread () {
  Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
    [int[]]$Id = $PSThreadList.Keys     # List of thread IDs
  )
  $Id | ForEach-Object { $PSThreadList.$_ }
}

Function Start-PSThread () {
  Param(
    [Parameter(Mandatory=$true, Position=0)]
    [ScriptBlock]$ScriptBlock,          # The script block to run in a new thread
    [Parameter(Mandatory=$false)]
    [String]$Name = "",                 # Optional thread name. Default: "PSThread$Id"
    [Parameter(Mandatory=$false)]
    [String]$Event = "",                # Optional thread completion event name. Default: None
    [Parameter(Mandatory=$false)]
    [Hashtable]$Variables = @{},        # Optional variables to copy into the script context.
    [Parameter(Mandatory=$false)]
    [String[]]$Functions = @(),         # Optional functions to copy into the script context.
    [Parameter(Mandatory=$false)]
    [Object[]]$Arguments = @()          # Optional arguments to pass to the script.
  )

  $Id = $script:PSThreadCount
  $script:PSThreadCount += 1
  if (!$Name.Length) {
    $Name = "PSThread$Id"
  }
  $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
  foreach ($VarName in $Variables.Keys) { # Copy the specified variables into the script initial context
    $value = $Variables.$VarName
    Write-Debug "Adding variable $VarName=[$($Value.GetType())]$Value"
    $var = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($VarName, $value, "")
    $InitialSessionState.Variables.Add($var)
  }
  foreach ($FuncName in $Functions) { # Copy the specified functions into the script initial context
    $Body = Get-Content function:$FuncName
    Write-Debug "Adding function $FuncName () {$Body}"
    $func = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($FuncName, $Body)
    $InitialSessionState.Commands.Add($func)
  }
  $RunSpace = [RunspaceFactory]::CreateRunspace($InitialSessionState)
  $RunSpace.Open()
  $PSPipeline = [powershell]::Create()
  $PSPipeline.Runspace = $RunSpace
  $PSPipeline.AddScript($ScriptBlock) | Out-Null
  $Arguments | ForEach-Object {
    Write-Debug "Adding argument [$($_.GetType())]'$_'"
    $PSPipeline.AddArgument($_) | Out-Null
  }
  $Handle = $PSPipeline.BeginInvoke() # Start executing the script
  if ($Event.Length) { # Do this after BeginInvoke(), to avoid getting the start event.
    Register-ObjectEvent $PSPipeline -EventName InvocationStateChanged -SourceIdentifier $Name -MessageData $Event
  }
  $PSThread = New-Object PSObject -Property @{
    Id = $Id
    Name = $Name
    Event = $Event
    RunSpace = $RunSpace
    PSPipeline = $PSPipeline
    Handle = $Handle
  }     # Return the thread description variables
  $script:PSThreadList[$Id] = $PSThread
  $PSThread
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Receive-PSThread                                          #
#                                                                             #
#   Description     Get the result of a thread, and optionally clean it up    #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#    2016-06-08 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Receive-PSThread () {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
    [PSObject]$PSThread,                # Thread descriptor object
    [Parameter(Mandatory=$false)]
    [Switch]$AutoRemove                 # If $True, remove the PSThread object
  )
  Process {
    if ($PSThread.Event -and $AutoRemove) {
      Unregister-Event -SourceIdentifier $PSThread.Name
      Get-Event -SourceIdentifier $PSThread.Name | Remove-Event # Flush remaining events
    }
    try {
      $PSThread.PSPipeline.EndInvoke($PSThread.Handle) # Output the thread pipeline output
    } catch {
      $_ # Output the thread pipeline error
    }
    if ($AutoRemove) {
      $PSThread.RunSpace.Close()
      $PSThread.PSPipeline.Dispose()
      $PSThreadList.Remove($PSThread.Id)
    }
  }
}

Function Remove-PSThread () {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
    [PSObject]$PSThread                 # Thread descriptor object
  )
  Process {
    $_ | Receive-PSThread -AutoRemove | Out-Null
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
#   Function        Receive-PipeMessage                                       #
#                                                                             #
#   Description     Wait for a message from a named pipe                      #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes           I tried keeping the pipe open between client connections, #
#                   but for some reason everytime the client closes his end   #
#                   of the pipe, this closes the server end as well.          #
#                   Any solution on how to fix this would make the code       #
#                   more efficient.                                           #
#                                                                             #
#   History                                                                   #
#    2016-05-25 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Receive-PipeMessage () {
  Param(
    [Parameter(Mandatory=$true)]
    [String]$PipeName           # Named pipe name
  )
  $PipeDir  = [System.IO.Pipes.PipeDirection]::In
  $PipeOpt  = [System.IO.Pipes.PipeOptions]::Asynchronous
  $PipeMode = [System.IO.Pipes.PipeTransmissionMode]::Message

  try {
    $pipe = $null       # Named pipe stream
    $pipe = New-Object system.IO.Pipes.NamedPipeServerStream($PipeName, $PipeDir, 1, $PipeMode, $PipeOpt)
    $sr = $null         # Stream Reader
    $sr = new-object System.IO.StreamReader($pipe)
    $pipe.WaitForConnection()
    $Message = $sr.Readline()
    $Message
  } catch {
    Write-Log "Error receiving pipe message: $_" -Level Error
  } finally {
    if ($sr) {
      $sr.Dispose() # Release resources
      $sr = $null   # Force the PowerShell garbage collector to delete the .net object
    }
    if ($pipe) {
      $pipe.Dispose() # Release resources
      $pipe = $null   # Force the PowerShell garbage collector to delete the .net object
    }
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Start-PipeHandlerThread                                   #
#                                                                             #
#   Description     Start a new thread waiting for control messages on a pipe #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes           The pipe handler script uses function Receive-PipeMessage.#
#                   This function must be copied into the thread context.     #
#                                                                             #
#                   The other functions and variables copied into that thread #
#                   context are not strictly necessary, but are useful for    #
#                   debugging possible issues.                                #
#                                                                             #
#   History                                                                   #
#    2016-06-07 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

$pipeThreadName = "Control Pipe Handler"

Function Start-PipeHandlerThread () {
  Param(
    [Parameter(Mandatory=$true)]
    [String]$pipeName,                  # Named pipe name
    [Parameter(Mandatory=$false)]
    [String]$Event = "ControlMessage"   # Event message
  )
  Start-PSThread -Variables @{  # Copy variables required by function Log() into the thread context
    # Remove log file
    #logDir = $logDir
    #logFile = $logFile
    currentUserName = $currentUserName
  } -Functions Now, Write-Log, Receive-PipeMessage -ScriptBlock {
    Param($pipeName, $pipeThreadName)
    try {
      Receive-PipeMessage "$pipeName" # Blocks the thread until the next message is received from the pipe
    } catch {
      Write-Log "$pipeThreadName # Error: $_" -Level Error
      throw $_ # Push the error back to the main thread
    }
  } -Name $pipeThreadName -Event $Event -Arguments $pipeName, $pipeThreadName
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Receive-PipeHandlerThread                                 #
#                                                                             #
#   Description     Get what the pipe handler thread received                 #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#    2016-06-07 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Receive-PipeHandlerThread () {
  Param(
    [Parameter(Mandatory=$true)]
    [PSObject]$pipeThread               # Thread descriptor
  )
  Receive-PSThread -PSThread $pipeThread -AutoRemove
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
#   Function        Add-BGP                                                   #
#                                                                             #
#   Description     Add BGP Route on the network card                         #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Add-Bgp()
{
  Param
  (
    [Parameter(Mandatory=$true)]
    $Route
  )

  # Manage IP Address
  $announce_route=Add-IP $route

  # Add route
  if ($announce_route) {
    Write-Log "Announce BGP network '$($route.Network)'" -AdditionalFields @($route.RouteName)
    if ((Get-BgpCustomRoute).Network -notcontains "$($route.Network)"){Add-BgpCustomRoute -Network "$($route.Network)"}
  }
}


#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        remove-BGP                                                #
#                                                                             #
#   Description     remove BGP Route on the network card                      #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function remove-Bgp()
{
  Param
  (
    [Parameter(Mandatory=$true)]
    $Route
  )

  # Remove IP
  Remove-IP $route

  # Remove BGP Route
  if ((Get-BgpCustomRoute).Network -contains "$($route.Network)"){
    Write-Log "Unannounce BGP network '$($route.Network)'" -AdditionalFields @($route.RouteName)
    Remove-BgpCustomRoute -network "$($route.Network)" -Force
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Add-IP                                                    #
#                                                                             #
#   Description     Add IP address on the network card                        #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Add-IP()
{
  Param
  (
    [Parameter(Mandatory=$true)]
    $Route
  )

  if($route.DynamicIpSetup) {
    #Add IP
    $IPAddress=$route.Network.split('/')[0]
    $Netmask=$route.Network.split('/')[1]
    #Add new IP (SkipAsSource:The addresses are not used for outgoing traffic and are not registered in DNS)
    if ((Get-NetIPAddress -InterfaceAlias "$($route.Interface)").IPAddress -notcontains "$IPAddress"){
      Write-Log "Add IP Address '$($route.Network)' on interface '$($route.Interface)'" -AdditionalFields @($route.RouteName)
      New-NetIPAddress -InterfaceAlias "$($route.Interface)" -IPAddress $IPAddress -PrefixLength $Netmask -SkipAsSource:$true -PolicyStore ActiveStore
      # Waiting IP to be mounted
      while ((Get-NetIPAddress -InterfaceAlias "$($route.Interface)" -IPAddress $IPAddress).AddressState -eq 'Tentative'){}
      if ((Get-NetIPAddress -InterfaceAlias "$($route.Interface)" -IPAddress $IPAddress).AddressState -eq 'Preferred') {
        Write-Log "IP Address '$($route.Network)' on interface '$($route.Interface)' successfully added" -AdditionalFields @($route.RouteName)
        $announce_route=$true
      } elseif ((Get-NetIPAddress -InterfaceAlias "$($route.Interface)" -IPAddress $IPAddress).AddressState -eq 'Duplicate') {
        $announce_route=$false
        Remove-NetIPAddress -IPAddress $IPAddress -Confirm:$false
        Write-Log "Duplicate IP - Unable to add IP Address '$($route.Network)' on interface '$($route.Interface)'" -Level Error -AdditionalFields @($route.RouteName)
        Write-Log "Set ArpRetryCount to '0' to avoid this error" -Level Warning
      } else {
        $announce_route=$false
        Write-Log "Unknown error - Unable to add IP Address '$($route.Network)' on interface '$($route.Interface)'" -Level Error -AdditionalFields @($route.RouteName)
      }
    } else {
      # IP already there, announce route
      $announce_route=$true
    }
  }
  else {
    # Always announce route
    $announce_route=$true
    Write-Log "IP Address '$($route.Network)' not managed by WinBGP Service" -Level Warning -AdditionalFields @($route.RouteName)
  }
  # Return status
  return $announce_route
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        remove-IP                                                 #
#                                                                             #
#   Description     Remove IP address on the network card                     #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Remove-IP()
{
  Param
  (
    [Parameter(Mandatory=$true)]
    $Route
  )
  if($route.DynamicIpSetup){
    #Remove IP
    $IPAddress=$route.Network.split('/')[0]
    if ((Get-NetIPAddress -InterfaceAlias "$($route.Interface)").IPAddress -contains "$IPAddress"){
      Write-Log "Remove IP Address '$($route.Network)' on interface '$($route.Interface)'" -AdditionalFields @($route.RouteName)
      Remove-NetIPAddress -IPAddress $IPAddress -Confirm:$false
    }
  }
  else {
    Write-Log "IP Address '$($route.Network)' not managed by WinBGP Service" -Level Warning -AdditionalFields @($route.RouteName)
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Write-Route                                               #
#                                                                             #
#   Description     Log Route information                                     #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Write-Route() {
  Param
  (
      [Parameter(Mandatory=$true)]
      $Route
  )
  Write-Log "Route Name : '$($route.Routename)'`nNetwork to Announce : '$($route.Network)'" -AdditionalFields @($Route.RouteName)
  #Display service to check if WithdrawOnDown is true
  if ($route.WithdrawOnDown) {
    if ($route.WithdrawOnDownCheck) {
      $pos = ($route.WithdrawOnDownCheck).IndexOf(":")
      $check_method = ($route.WithdrawOnDownCheck).Substring(0, $pos)
      $check_name = ($route.WithdrawOnDownCheck).Substring($pos+2)
      # Rewrite $check_name for logging if check is custom
      if ($check_method -eq 'custom') {
        $check_name='check'
      }
      $Msg="WithdrawOnDownCheck - Method: '$check_method' - Name: '$check_name'"
      if($route.Interval) {
        $Msg+=" - Interval: '$($route.Interval)'"
      }

      Write-Log $Msg -AdditionalFields @($Route.RouteName)
    }
    else {
      Write-Log "WithdrawOnDownCheck cannot be empty when WithdrawOnDown is set to true" -Level Warning -AdditionalFields @($Route.RouteName)
    }
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Add-RoutePolicy                                           #
#                                                                             #
#   Description     Add routing policies                                      #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Add-RoutePolicy() {
  Param
  (
      [Parameter(Mandatory=$true)]
      $Route,
      [Parameter(Mandatory=$true)]
      $Peers
  )

  # Generate routing policy parameters
  $params = @{
    Name        = $route.RouteName;
    MatchPrefix = $route.Network;
    PolicyType  = 'ModifyAttribute';
    NewMED      = $route.Metric;
  }
  # Log information
  Write-Log "BGP Routing Policy - Metric: '$($route.Metric)'" -AdditionalFields @($Route.RouteName)
  # If Community is specified
  if ($route.Community) {
    $params.add('AddCommunity',$route.Community)
    Write-Log "BGP Routing Policy - Community: '$($Route.Community)'" -AdditionalFields @($Route.RouteName)
  }
  # If NextHop is specified
  if ($route.NextHop) {
    $params.add('NewNextHop',$route.NextHop)
    Write-Log "BGP Routing Policy - NextHop: '$($Route.NextHop)'" -AdditionalFields @($Route.RouteName)
  }

  # Compare routing policy to avoid deleting each time
  # Checking if Routing policy already exist
  # If there is a Routing policy, cleaning it
  $BGPRoutingPolicy=get-BgpRoutingPolicy -Name $route.RouteName -ErrorAction SilentlyContinue
  if (($BGPRoutingPolicy.PolicyType -ne 'ModifyAttribute') -or ($BGPRoutingPolicy.MatchPrefix -ne $route.Network) -or ($BGPRoutingPolicy.NewMED -ne $route.Metric) -or ((Compare-Object -DifferenceObject $BGPRoutingPolicy.AddCommunity -ReferenceObject $route.Community).count -ne 0) -or ($BGPRoutingPolicy.NewNextHop -ne $Route.NextHop)) {
    # If policy exist
    if ($BGPRoutingPolicy) {
      # Remove wrongly configured
      Write-Log "BGP Routing Policy [$($Route.RouteName)] already configured - Cleaning (This situation may occur if the service was not correctly stopped)" -Level Warning -AdditionalFields @($Route.RouteName)
      Remove-BgpRoutingPolicy -Name $route.RouteName -Force
    }
    # Add new routing policy
    Write-Log "Creating BGP Routing Policy '$($Route.RouteName)'" -AdditionalFields @($Route.RouteName)
    Add-BgpRoutingPolicy @params -Force
  }

  # Declare routing policy on each peer
  ForEach ($peer in $Peers) {
    if ((Get-BgpPeer -PeerName $peer.Peername).EgressPolicyList -contains $Route.RouteName) {
      Write-Log "BGP Routing Policy on Peer $($peer.Peername)" -AdditionalFields @($Route.RouteName)
    } else {
      Write-Log "Adding BGP Routing Policy on Peer $($peer.Peername)" -AdditionalFields @($Route.RouteName)
      Add-BgpRoutingPolicyForPeer -PeerName $peer.Peername -PolicyName $Route.RouteName -Direction 'Egress' -Force
    }
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Start-API                                                 #
#                                                                             #
#   Description     Starting API Engine                                       #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Start-API() {
  Param
  (
      [Parameter(Mandatory=$true)]
      $ApiConfiguration
  )
  # Start API
  Write-Log "Starting API engine"
  # ArgumentList (,$ApiConfiguration) is to handle array as argument
  Start-Job -Name 'API' -FilePath "$installDir\$serviceDisplayName-API.ps1" -ArgumentList (,$ApiConfiguration)
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Stop-API                                                  #
#                                                                             #
#   Description     Stopping API Engine                                       #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#
function Stop-API() {
  # Stop API
  Write-Log "Stopping API engine"
  ### IMPROVEMENT - To be check if we can kill API properly ###
  $ProcessID=$null
  $ApiPID=$null
  # Get service PID
  $ProcessID=(Get-CimInstance Win32_Process -Filter "name = 'powershell.exe'" -OperationTimeoutSec 1 | Where-Object {$_.CommandLine -like "*'$installDir\$engineName.ps1' -Service*"}).ProcessId
  if ($ProcessID) {
  # Get API PID
    $ApiPID=(Get-WmiObject win32_process -filter "Name='powershell.exe' AND ParentProcessId=$ProcessID").ProcessId
    if ($ApiPID) {
      Stop-Process -Id $ApiPID -Force -ErrorAction SilentlyContinue
    }
  }
  Stop-Job -Name 'API' -ErrorAction SilentlyContinue
  Remove-Job -Name 'API' -Force -ErrorAction SilentlyContinue
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

# Remove file log
# if ($Setup) {Log ""}    # Insert one blank line to separate test sessions logs
# Log $MyInvocation.Line # The exact command line that was used to start us

# The following commands write to the event log, but we need to make sure the PSService source is defined.
New-EventLog -LogName $logName -Source $serviceName -ea SilentlyContinue

# Workaround for PowerShell v2 bug: $PSCmdlet Not yet defined in Param() block
$Status = ($PSCmdlet.ParameterSetName -eq 'Status')

if ($SCMStart) {                # The SCM tells us to start the service
  # Do whatever is necessary to start the service script instance
  Write-Log -Message "SCMStart: Starting script '$scriptFullName' -Service"
  Start-Process PowerShell.exe -ArgumentList ("-c & '$scriptFullName' -Service")
  # Waiting for Pipe to be started before confirming service is successfully started
  while([System.IO.Directory]::GetFiles("\\.\\pipe\\") -notcontains "\\.\\pipe\\$($pipeName)") {
    # Wait 1 seconds before checking again
    Start-Sleep -Seconds 1
  }
  return
}

if ($SCMResume) {                # The SCM tells us to resume the service
  # Do whatever is necessary to resume the service script instance
  Write-Log -Message "SCMResume: Resuming script '$scriptFullName' -Service"
  Start-Process PowerShell.exe -ArgumentList ("-c & '$scriptFullName' -Service")
  # Waiting for Pipe to be started before confirming service is successfully resumed
  while([System.IO.Directory]::GetFiles("\\.\\pipe\\") -notcontains "\\.\\pipe\\$($pipeName)") {
    # Wait 1 seconds before checking again
    Start-Sleep -Seconds 1
  }
  return
}

if ($SCMStop) {         #  The SCM tells us to stop the service
  # Do whatever is necessary to stop the service script instance
  Write-Log -Message "SCMStop: Stopping script $scriptName -Service"
  # Send an stop message to the service instance
  Send-PipeMessage $pipeName 'stop'
  # Waiting for Pipe to be stopped before confirming service is successfully stopped
  while([System.IO.Directory]::GetFiles("\\.\\pipe\\") -contains "\\.\\pipe\\$($pipeName)") {
    # Wait 1 seconds before checking again
    Start-Sleep -Seconds 1
  }
  return
}

if ($SCMSuspend) {         #  The SCM tells us to suspend the service
  # Do whatever is necessary to stop the service script instance
  Write-Log -Message "SCMSuspend: Suspending script $scriptName -Service"
  # Send an suspend message to the service instance
  Send-PipeMessage $pipeName 'suspend'
  # Waiting for Pipe to be stopped before confirming service is successfully suspended
  while([System.IO.Directory]::GetFiles("\\.\\pipe\\") -contains "\\.\\pipe\\$($pipeName)") {
    # Wait 1 seconds before checking again
    Start-Sleep -Seconds 1
  }
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

if ($Service) {                 # Run the service
  Write-Log -Message "Beginning background job"
  # Do the service background job
  try {
    ######### TO DO: Implement your own service code here. ##########
    # Now enter the main service event loop
    Write-Log -Message "Starting WinBGP Engine"

    # Checking prerequisites routing status
    if ((Get-RemoteAccess).RoutingStatus -ne 'Installed') {
      Write-Log -Message "Routing feature (Remote access) is required to run WinBGP" -Level Error
      exit 1
    }

    # Read configuration
    if (Test-ConfigurationFile) {
      $configuration = Get-Content -Path $configdir | ConvertFrom-Json 
      Write-Log "Loading configuration file '$($configdir)'"
    } else {
      Write-Log "Configuration file '$($configdir)' is not valid" -Level Warning
      Write-Log "Stopping $($serviceInternalName) process" -Level Error
      # Forcing stop process so service will know that process is not running
      Stop-Process -Name $serviceInternalName -Force
      exit 1
    }

    # Log Interval information
    Write-Log "Global Interval: '$($configuration.global.Interval)' seconds"
    Write-Log "Global Timeout: '$($configuration.global.Timeout)' seconds"
    Write-Log "Global Rise: '$($configuration.global.Rise)' checks"
    Write-Log "Global Fall: '$($configuration.global.Fall)' checks"
    Write-Log "Global Metric: '$($configuration.global.Metric)'"

    # Parse all routes
    foreach ($route in $configuration.routes)
    {
      # Log Route information
      Write-Route $route
      # Add default interval value if no interval is specified on the route
      if(!($route.Interval)) {
        $route | Add-member -MemberType NoteProperty -Name 'Interval' -Value $configuration.global.Interval
      }
      # Add default Metric if no metric is specified on the route
      if(!($route.Metric)) {
        $route | Add-member -MemberType NoteProperty -Name 'Metric' -Value $configuration.global.Metric
      }
      # Add default Rise if no Rise is specified on the route
      if(!($route.Rise)) {
        $route | Add-member -MemberType NoteProperty -Name 'Rise' -Value $configuration.global.Rise
      }
      # Add default Fall if no Fall is specified on the route
      if(!($route.Fall)) {
        $route | Add-member -MemberType NoteProperty -Name 'Fall' -Value $configuration.global.Fall
      }
    }

    #BGP Router (Local)
    #Getting BGP Router (Local) Status
    $BgpRouterStatus = $null
    try {
      $BgpRouter=Get-BgpRouter -ErrorAction SilentlyContinue
    }
    catch {
      #If BGP Router (Local) is not configured, catch it
      $BgpRouterStatus=($_).ToString()
    }
    #Checking if BGP Router (Local) is correctly configured
    if (($BgpRouter.BgpIdentifier -eq $configuration.router.BgpIdentifier) -and ($BgpRouter.LocalASN -eq $configuration.router.LocalASN)) {
      Write-Log "BGP Router (local) [BgpIdentifier: $($configuration.router.BgpIdentifier) - LocalASN: $($configuration.router.LocalASN)]"
    } else {
      #BGP Router (Local) not correctly configured, remove it
      if ($BgpRouterStatus -ne 'BGP is not configured.') {
        Write-Log "BGP Router (local) not correctly configured - Cleaning (This situation may occur if the service was not correctly stopped)" -Level Warning
        Remove-BgpRouter -Force
      }
      #Create BGP Router
      Write-Log "Adding BGP Router (local) [BgpIdentifier: $($configuration.router.BgpIdentifier) - LocalASN: $($configuration.router.LocalASN)]"
      Add-BgpRouter -BgpIdentifier $configuration.router.BgpIdentifier -LocalASN $configuration.router.LocalASN -Force
    }
    #Adding Peering
    ForEach ($peer in $configuration.peers)
    {
      #Checking if Peering already exist
      if (((Get-BgpPeer -Name $peer.Peername -ErrorAction SilentlyContinue).LocalIPAddress -eq $peer.LocalIP) -and ((Get-BgpPeer -Name $peer.Peername -ErrorAction SilentlyContinue).LocalASN -eq $peer.LocalASN) -and ((Get-BgpPeer -Name $peer.Peername -ErrorAction SilentlyContinue).PeerIPAddress -eq $peer.PeerIP) -and ((Get-BgpPeer -Name $peer.Peername -ErrorAction SilentlyContinue).PeerASN -eq $peer.PeerASN)) {
        Write-Log "BGP Peering '$($peer.Peername)'"
      } else {
        #If there is a Peering but not correctly configured, cleaning it
        if (Get-BgpPeer -Name $peer.Peername -ErrorAction SilentlyContinue) {
        Write-Log "BGP Peer '$($peer.Peername)' not correctly configured - Cleaning (This situation may occur if the service was not correctly stopped)" -Level Warning
        Remove-BgpPeer -Name $peer.Peername -Force
        }
        Write-Log "Adding BGP Peer '$($peer.Peername)' [IP: $($peer.PeerIP) - LocalASN: $($peer.LocalASN) - PeerASN: $($peer.PeerASN)]"
        Add-BgpPeer -LocalIPAddress $peer.LocalIP -PeerIPAddress $peer.PeerIP -LocalASN $peer.LocalASN -PeerASN $peer.PeerASN -Name $peer.Peername
      }
    }

    #If there is a maintenance from previous instance (restart of service or reboot), import it
    if(Test-Path -Path $FunctionCliXml) {
      #Import variable
      $maintenance=Import-CliXml -Path $FunctionCliXml
    }
    #Otherwise, initialize variable
    else {
      $maintenance = @{}
    }
    #Parse all routes
    ForEach ($route in $configuration.routes) {
      # Routing policies
      Add-RoutePolicy -Route $route -Peers $configuration.peers
      #Check if route is in maintenance mode
      if ($maintenance.($route.RouteName)) {
        #Maintenance
        Write-Log "Route '$($route.RouteName)' is in maintenance mode" -AdditionalFields @($route.RouteName)
      } else {
        # Starting HealthCheck Job
        Write-Log "Starting HealthCheck Process" -AdditionalFields @($route.RouteName)
        Start-Job -Name $route.RouteName -FilePath "$installDir\WinBGP-HealthCheck.ps1" -ArgumentList $route
      }
    }

    # API
    if ($configuration.global.Api) {
      # Start API
      Start-API -ApiConfiguration $configuration.api
    }

    # Watchdog timer
    # Start a periodic timer
    $timerName = "Sample service timer"
    $period = 30 # seconds
    $timer = new-object System.Timers.Timer
    $timer.Interval = ($period * 1000) # Milliseconds
    $timer.AutoReset = $true # Make it fire repeatedly
    Register-ObjectEvent $timer -EventName Elapsed -SourceIdentifier $timerName -MessageData "TimerTick"
    $timer.start() # Must be stopped in the finally block

    Write-Log -Message "WinBGP Engine successfully started"
    # Start the control pipe handler thread
    $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
    ###############
    do { # Keep running until told to exit by the -Stop handler
      $event = Wait-Event # Wait for the next incoming event
      $source = $event.SourceIdentifier
      $message = $event.MessageData
      $eventTime = $event.TimeGenerated.TimeofDay
      Write-Debug "Event at $eventTime from ${source}: $message"
      $event | Remove-Event # Flush the event from the queue
      switch ($message) {
        "ControlMessage" { # Required. Message received by the control pipe thread
          $state = $event.SourceEventArgs.InvocationStateInfo.state
          Write-Debug "$script -Service # Thread $source state changed to $state"
          switch ($state) {
            "Completed" {
              $message = Receive-PipeHandlerThread $pipeThread
              Write-Log "Received control message: $Message"
              # Reload
              if ($message -eq "reload") {
                # Store old configuration
                $oldConfiguration = $configuration
                # If Json is valid, reloading
                if (Test-ConfigurationFile) {
                  Write-Log "Reloading configuration file '$($configdir)'"
                  # Reload configuration file
                  $configuration = Get-Content -Path $configdir | ConvertFrom-Json
                  # Parse all routes
                  foreach ($route in $configuration.routes)
                  {
                    # Add default value interval value if no interval value is specified on the route
                    if(!($route.Interval)) {
                      $route | Add-member -MemberType NoteProperty -Name 'Interval' -Value $configuration.global.Interval
                    }
                    # Add default Metric if no metric is specified on the route
                    if(!($route.Metric)) {
                      $route | Add-member -MemberType NoteProperty -Name 'Metric' -Value $configuration.global.Metric
                    }
                    # Add default Rise if no Rise is specified on the route
                    if(!($route.Rise)) {
                      $route | Add-member -MemberType NoteProperty -Name 'Rise' -Value $configuration.global.Rise
                    }
                    # Add default Fall if no Fall is specified on the route
                    if(!($route.Fall)) {
                      $route | Add-member -MemberType NoteProperty -Name 'Fall' -Value $configuration.global.Fall
                    }
                  }
                  # Config (Global) - Only logging changes
                  if (Compare-Object -ReferenceObject $oldConfiguration.global.PSObject.Properties -DifferenceObject $configuration.global.PSObject.Properties -PassThru) {
                    # Manage global Interval
                    if ($configuration.global.Interval -ne $oldConfiguration.global.Interval) {
                      Write-Log "Global configuration - Old Interval: '$($oldConfiguration.global.Interval)' - New Interval: '$($configuration.global.Interval)'"
                    }
                    # Manage global Rise
                    if ($configuration.global.Rise -ne $oldConfiguration.global.Rise) {
                      Write-Log "Global configuration - Old Rise: '$($oldConfiguration.global.Rise)' - New Rise: '$($configuration.global.Rise)'"
                    }
                    # Manage global Fall
                    if ($configuration.global.Fall -ne $oldConfiguration.global.Fall) {
                      Write-Log "Global configuration - Old Fall: '$($oldConfiguration.global.Fall)' - New Fall: '$($configuration.global.Fall)'"
                    }
                  }
                  # Manage API (Enable/Disable)
                  if ($configuration.global.Api -ne $oldConfiguration.global.Api) {
                    Write-Log "Global configuration - Old API: '$($oldConfiguration.global.Api)' - New API: '$($configuration.global.Api)'"
                    if ($configuration.global.Api) {
                      # Start Api
                      Start-API -ApiConfiguration $configuration.api
                    } else {
                      ### TO BE IMPROVED because killing all healthchecks jobs ###
                      # Stop Api
                      Stop-API
                    }
                  } else { # Manage API config change
                    # Only if API is enabled
                    if ($configuration.global.Api) {
                      if (Compare-Object -ReferenceObject $oldConfiguration.api.PSObject.Properties -DifferenceObject $configuration.api.PSObject.Properties -PassThru) {
                        # Log
                        Write-Log "API configuration change - Restarting API engine"
                        # Stop Api
                        Stop-API
                        # Start Api
                        Start-API -ApiConfiguration $configuration.api
                      }
                    }
                  }

                  # Router (Local)
                  if (Compare-Object -ReferenceObject $oldConfiguration.router.PSObject.Properties -DifferenceObject $configuration.router.PSObject.Properties -PassThru) {
                    # Only log
                    Write-Log "Router configuration change require a service restart" -Level Warning
                  }
                  # Routes
                  $routesReloaded=Compare-Object -ReferenceObject $oldConfiguration.routes -DifferenceObject $configuration.routes -Property 'RouteName' -PassThru -IncludeEqual | Select-Object RouteName,SideIndicator
                  foreach ($routeReloaded in $routesReloaded) {
                    # Old route
                    $oldRoute=$oldConfiguration.routes | Where-Object {$_.RouteName -eq $routeReloaded.RouteName}
                    # New route
                    $route=$configuration.routes | Where-Object {$_.RouteName -eq $routeReloaded.RouteName}
                    if ($routeReloaded.SideIndicator -eq '<=') {
                      Write-Log "Route '$($routeReloaded.RouteName)' removed" -AdditionalFields @($oldRoute.RouteName)
                      # Stopping HealthCheck Job
                      Write-Log "Stopping HealthCheck Process" -AdditionalFields @($oldRoute.RouteName)
                      Stop-Job -Name $oldRoute.RouteName
                      Remove-Job -Name $oldRoute.RouteName -Force
                      # Remove routing policy
                      if (get-BgpRoutingPolicy -Name $oldRoute.RouteName -ErrorAction SilentlyContinue) {
                        Write-Log "Removing BGP Routing Policy [$($oldRoute.RouteName)]" -AdditionalFields @($oldRoute.RouteName)
                        Remove-BgpRoutingPolicy -Name $oldRoute.RouteName -Force
                      }
                      # Stop Announce the route from Json configuration
                      if ((Get-BgpCustomRoute).Network -contains "$($oldRoute.Network)") 
                      {
                        Write-Log -Message "Stopping route '$($oldRoute.RouteName)'" -AdditionalFields @($oldRoute.RouteName)
                        # Call function to remove BGP route
                        remove-Bgp -Route $oldRoute
                      }
                      # If route is in maintenance
                      if ($maintenance.($oldRoute.RouteName)) {
                        Write-Log "Stopping maintenance for route '$($oldRoute.RouteName)'" -AdditionalFields @($oldRoute.RouteName)
                        $maintenance.Remove($oldRoute.RouteName)
                        # Export maintenance variable on each change (To be moved to function)
                        $maintenance | Export-CliXml -Path $FunctionCliXml -Force
                      }
                    } elseif ($routeReloaded.SideIndicator -eq '=>') {
                      Write-Log "Route '$($routeReloaded.RouteName)' added" -AdditionalFields @($Route.RouteName)
                      # Log Route information
                      Write-Route $route
                      # Create routing policies
                      Add-RoutePolicy -Route $route -Peers $configuration.peers
                      # Starting HealthCheck Job
                      Write-Log "Starting HealthCheck Process" -AdditionalFields @($route.RouteName)
                      Start-Job -Name $route.RouteName -FilePath "$installDir\WinBGP-HealthCheck.ps1" -ArgumentList $route
                    } elseif ($routeReloaded.SideIndicator -eq '==') {
                      # Comparing old route and new route to check if there are updates to perform
                      if (($route.Network -ne $oldRoute.Network) -or ($route.DynamicIpSetup -ne $oldRoute.DynamicIpSetup) -or ($route.Interface -ne $oldRoute.Interface) -or ($route.Interval -ne $oldRoute.Interval) -or (Compare-Object -ReferenceObject $oldRoute.Community -DifferenceObject $route.Community) -or ($route.Metric -ne $oldRoute.Metric) -or ($route.NextHop -ne $oldRoute.NextHop) -or ($route.WithdrawOnDown -ne $oldRoute.WithdrawOnDown) -or ($route.WithdrawOnDownCheck -ne $oldRoute.WithdrawOnDownCheck)) {
                        # Log changes
                        Write-Log "Route '$($routeReloaded.RouteName)' updated" -AdditionalFields @($Route.RouteName)
                        # Manage WithdrawOnDown change
                        if ($route.WithdrawOnDown -ne $oldRoute.WithdrawOnDown) {
                          Write-Log "WithdrawOnDown change - Old WithdrawOnDown: '$($oldRoute.WithdrawOnDown)' - New WithdrawOnDown: '$($route.WithdrawOnDown)'"  -AdditionalFields @($Route.RouteName)
                          # If WithdrawOnDown change, restart healthcheck
                          Write-Log "Restarting HealthCheck Process" -AdditionalFields @($route.RouteName)
                          # Stopping HealthCheck Job
                          Stop-Job -Name $oldRoute.RouteName
                          Remove-Job -Name $oldRoute.RouteName -Force
                          # Starting HealthCheck Job
                          Start-Job -Name $route.RouteName -FilePath "$installDir\WinBGP-HealthCheck.ps1" -ArgumentList $route
                        }
                        # Manage WithdrawOnDownCheck change (Only if WithdrawOnDown was enabled and it still enabled)
                        if ($route.WithdrawOnDown -and $oldRoute.WithdrawOnDown) {
                          if ($route.WithdrawOnDownCheck -ne $oldRoute.WithdrawOnDownCheck) {
                            Write-Log "WithdrawOnDownCheck change - Old Check: '$($oldRoute.WithdrawOnDownCheck)' - New Check: '$($route.WithdrawOnDownCheck)'"  -AdditionalFields @($Route.RouteName)
                            Write-Log "Restarting HealthCheck Process" -AdditionalFields @($route.RouteName)
                            # Stopping HealthCheck Job
                            Stop-Job -Name $oldRoute.RouteName
                            Remove-Job -Name $oldRoute.RouteName -Force
                            # Starting HealthCheck Job
                            Start-Job -Name $route.RouteName -FilePath "$installDir\WinBGP-HealthCheck.ps1" -ArgumentList $route
                          }
                        }
                        # Manage interval change
                        if ($route.Interval -ne $oldRoute.Interval) {
                          Write-Log "Interval change - Old Interval: '$oldRouteInterval' - New Interval: '$period'"  -AdditionalFields @($Route.RouteName)
                          # Stopping HealthCheck Job
                          Write-Log "Stopping HealthCheck Process" -AdditionalFields @($oldRoute.RouteName)
                          Stop-Job -Name $oldRoute.RouteName
                          Remove-Job -Name $oldRoute.RouteName -Force
                          # Starting HealthCheck Job
                          Write-Log "Starting HealthCheck Process" -AdditionalFields @($route.RouteName)
                          Start-Job -Name $route.RouteName -FilePath "$installDir\WinBGP-HealthCheck.ps1" -ArgumentList $route
                        }
                        # Manage network change
                        if ($route.Network -ne $oldRoute.Network) {
                          Write-Log "Network change - Old Network: '$($oldRoute.Network)' - New Network: '$($Route.Network)'" -AdditionalFields @($Route.RouteName)
                          # Stop Announce the route from Json configuration
                          if ((Get-BgpCustomRoute).Network -contains "$($oldRoute.Network)") 
                          {
                            # Removing old network
                            Write-Log -Message "Stopping route '$($oldRoute.RouteName)'" -AdditionalFields @($oldRoute.RouteName)
                            # Call function to remove BGP route
                            remove-Bgp -Route $oldRoute
                            # Adding new network
                            Write-Log -Message "Starting route '$($route.RouteName)'" -AdditionalFields @($Route.RouteName)
                            # Call function to remove BGP route
                            Add-Bgp -Route $Route
                          }
                        }
                        # Manage DynamicIpSetup change
                        if ($route.DynamicIpSetup -ne $oldRoute.DynamicIpSetup) {
                          Write-Log "Old DynamicIpSetup: '$($oldRoute.DynamicIpSetup)' - New DynamicIpSetup: '$($Route.DynamicIpSetup)'" -AdditionalFields @($Route.RouteName)
                          # Only if DynamicIpSetup was enabled and is now disabled
                          if (($oldRoute.DynamicIpSetup) -and (!($route.DynamicIpSetup))) {
                            # Remove IP on interface
                            Remove-IP $oldRoute
                          } else { # Only if DynamicIpSetup is now enabled and was previously disabled
                            # Add IP on interface
                            Add-IP $route
                          }
                        }
                        # Manage Interface change
                        if ($route.Interface -ne $oldRoute.Interface) {
                          Write-Log "Old Interface: '$($oldRoute.Interface)' - New Interface: '$($Route.Interface)'" -AdditionalFields @($Route.RouteName)
                          # Update required only if dynamic setup was enabled
                          Remove-IP $oldRoute
                          # Add IP on new interface
                          Add-IP $route
                        }
                        # Manage policy change
                        if ((Compare-Object -ReferenceObject $oldRoute.Community -DifferenceObject $route.Community) -or ($route.Metric -ne $oldRoute.Metric) -or ($route.NextHop -ne $oldRoute.NextHop)) {
                          # If Metric is specified for the route; Otherwise, use default value
                          if($route.Metric) {
                            $Metric = $route.Metric # seconds
                          } else {
                            $Metric = $configuration.global.Metric
                          }
                          # Generate routing policy parameters
                          $params = @{
                            Name        = $route.RouteName;
                            MatchPrefix = $route.Network;
                            PolicyType  = 'ModifyAttribute';
                            NewMED      = $Metric;
                          }
                          # If Metric change
                          if ($route.Metric -ne $oldRoute.Metric) {
                            # If Metric was not defined on old route, it was using default value
                            if($oldRoute.Metric) {
                              $oldRouteMetric=$oldRoute.Metric
                            } else {
                              $oldRouteMetric=$configuration.global.Metric
                            }
                            Write-Log "BGP Routing Policy - Old Metric: '$oldRouteMetric' - New Metric: '$Metric'" -AdditionalFields @($Route.RouteName)
                          }
                          # If Community is specified
                          if ($route.Community) {
                            $params.add('AddCommunity',$route.Community)
                            if (Compare-Object -ReferenceObject $oldRoute.Community -DifferenceObject $route.Community) {
                              Write-Log "BGP Routing Policy - Old Community: '$($oldRoute.Community)' - New Community: '$($Route.Community)'" -AdditionalFields @($Route.RouteName)
                            }
                          }        
                          # If NextHop is specified
                          if ($route.NextHop) {
                            $params.add('NewNextHop',$route.NextHop)
                            if ($route.NextHop -ne $oldRoute.NextHop) {
                              Write-Log "BGP Routing Policy - Old NextHop: '$($oldRoute.NextHop)' - New NextHop: '$($Route.NextHop)'" -AdditionalFields @($Route.RouteName)
                            }
                          }
                          # If Routing policy exist, update it
                          if (get-BgpRoutingPolicy -Name $route.RouteName -ErrorAction SilentlyContinue) {
                            Write-Log "Updating BGP Routing Policy '$($Route.RouteName)'" -AdditionalFields @($Route.RouteName)
                            Set-BgpRoutingPolicy @params -Force
                          } else { # Otherwise, create it
                            Write-Log "Creating BGP Routing Policy '$($Route.RouteName)'" -AdditionalFields @($Route.RouteName)
                            Add-BgpRoutingPolicy @params -Force
                            # Declare routing policy on each peer
                            ForEach ($peer in $configuration.peers) {
                              Write-Log "Adding BGP Routing Policy on Peer $($peer.Peername)" -AdditionalFields @($Route.RouteName)
                              Add-BgpRoutingPolicyForPeer -PeerName $peer.Peername -PolicyName $Route.RouteName -Direction 'Egress' -Force
                            }
                          }
                        }
                      }
                    }
                  }
                  # Peers
                  $peersReloaded=Compare-Object -ReferenceObject $oldConfiguration.peers -DifferenceObject $configuration.peers -Property 'PeerName' -PassThru -IncludeEqual | Select-Object PeerName,SideIndicator
                  foreach ($peerReloaded in $peersReloaded) {
                    # Old peer
                    $oldPeer=$oldConfiguration.peers | Where-Object {$_.PeerName -eq $peerReloaded.PeerName}
                    # New peer
                    $peer=$configuration.peers | Where-Object {$_.PeerName -eq $peerReloaded.PeerName}
                    if ($peerReloaded.SideIndicator -eq '<=') {
                      Write-Log "Peer '$($peerReloaded.PeerName)' removed"
                      if (Get-BgpPeer -Name $oldPeer.Peername -ErrorAction SilentlyContinue) {
                        Write-Log "Removing BGP Peer '$($oldPeer.Peername)'"
                        Remove-BgpPeer -Name $oldPeer.PeerName -Force
                        }
                    } elseif ($peerReloaded.SideIndicator -eq '=>') {
                      Write-Log "Peer '$($peerReloaded.PeerName)' added"
                      Write-Log "Adding BGP Peer '$($peer.Peername)'"
                      Add-BgpPeer -LocalIPAddress $peer.LocalIP -PeerIPAddress $peer.PeerIP -LocalASN $peer.LocalASN -PeerASN $peer.PeerASN -Name $peer.Peername
                      Get-BgpRoutingPolicy | Add-BgpRoutingPolicyForPeer -PeerName $peer.Peername -Direction 'Egress' -Force       
                      Write-Log "Adding BGP Routing Policy on Peer $($peer.Peername)"
                    } elseif ($peerReloaded.SideIndicator -eq '==') {
                      # Removing unwanted attribute
                      $oldPeer.PSObject.Properties.Remove('SideIndicator')
                      # Comparing
                      if (Compare-Object -ReferenceObject $oldPeer.PSObject.Properties -DifferenceObject $peer.PSObject.Properties -PassThru) {
                        Write-Log "Peer '$($peerReloaded.PeerName)' updated"
                        if (Get-BgpPeer -Name $oldPeer.Peername -ErrorAction SilentlyContinue) {
                          Write-Log "Removing BGP Peer '$($oldPeer.Peername)'"
                          Remove-BgpPeer -Name $oldPeer.PeerName -Force
                        }
                        Write-Log "Adding BGP Peer '$($peer.Peername)'"
                        Add-BgpPeer -LocalIPAddress $peer.LocalIP -PeerIPAddress $peer.PeerIP -LocalASN $peer.LocalASN -PeerASN $peer.PeerASN -Name $peer.Peername
                        Get-BgpRoutingPolicy | Add-BgpRoutingPolicyForPeer -PeerName $peer.Peername -Direction 'Egress' -Force       
                        Write-Log "Adding BGP Routing Policy on Peer $($peer.Peername)"
                      }
                    }
                  }
                } else {
                  Write-Log "Reload aborted - Configuration file '$($configdir)' is not a valid JSON file" -Level Warning
                }
                $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
              }
              #Start/Stop mode
              elseif ($message -like "route*")
              {
                $route_to_control=$message.split(' ')[1]
                $control_action=$message.split(' ')[2]
                # Grabbing route
                $route_control=$configuration.routes | Where-Object {$_.RouteName -eq $route_to_control}
                if ($control_action -eq 'start') {
                  # Control route announcement if maintenance is false
                  if (!$maintenance.($route_control.RouteName)) {
                    # Announce the route if there is no route
                    if ((Get-BgpCustomRoute).Network -notcontains "$($route_control.Network)")
                    {
                      Write-Log -Message "Starting route '$($route_control.RouteName)'" -AdditionalFields @($route_control.RouteName)
                      # Call function to start BGP route
                      Add-BGP -Route $route_control
                    }
                  } else {
                    Write-Log -Message "Route in maintenance - Skipping starting" -AdditionalFields @($route_control.RouteName)
                  }
                }
                elseif ($control_action -eq 'stop') {
                  # Control route announcement if maintenance is false
                  if (!$maintenance.($route_control.RouteName)) {
                    # Stop Announce the route
                    if ((Get-BgpCustomRoute).Network -contains "$($route_control.Network)") 
                    {
                      Write-Log -Message "Stopping route '$($route_control.RouteName)'" -AdditionalFields @($route_control.RouteName)
                      # Call function to remove BGP route
                      remove-Bgp -Route $route_control
                    }
                  } else {
                    Write-Log -Message "Route in maintenance - Skipping stopping" -AdditionalFields @($route_control.RouteName)
                  }
                }
              $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
              }
              #Maintenance mode
              elseif ($message -like "maintenance*")
              {
                $route_in_maintenance=$message.split(' ')[1]
                $control_action=$message.split(' ')[2]
                # Grabbing route
                $route_maintenance=$configuration.routes | Where-Object {$_.RouteName -eq $route_in_maintenance}
                if ($control_action -eq 'start') {
                  #If route is not in maintenance
                  if (!($maintenance.($route_maintenance.RouteName))) {
                    Write-Log "Starting maintenance for route '$($route_maintenance.RouteName)'" -AdditionalFields @($route_maintenance.RouteName)
                    # Add timestamp for monitoring purpose
                    $MaintenanceTimestamp=Get-Date
                    $maintenance.Add($route_maintenance.RouteName,$MaintenanceTimestamp)
                    # Export maintenance variable on each change (To be moved to function)
                    $maintenance | Export-CliXml -Path $FunctionCliXml -Force
                    # Stopping HealthCheck Job
                    Write-Log "Stopping HealthCheck Process" -AdditionalFields @($route_maintenance.RouteName)
                    Stop-Job -Name $route_maintenance.RouteName
                    Remove-Job -Name $route_maintenance.RouteName -Force
                    # Removing route
                    if ((Get-BgpCustomRoute).Network -contains "$($route_maintenance.Network)") {
                      remove-Bgp -Route $route_maintenance
                    }
                    else {
                      Write-Log "BGP network already unannounced '$($route_maintenance.Network)'" -Level Warning
                    }
                  }
                  else {
                    Write-Log "Route '$($route_maintenance.RouteName)' already in maintenance mode" -Level Warning
                  }
                }
                elseif ($control_action -eq 'stop') {
                  #If route is in maintenance
                  if ($maintenance.($route_maintenance.RouteName)) {
                    Write-Log "Stopping maintenance for route '$($route_maintenance.RouteName)'" -AdditionalFields @($route_maintenance.RouteName)
                    $maintenance.Remove($route_maintenance.RouteName)
                    # Export maintenance variable on each change (To be moved to function)
                    $maintenance | Export-CliXml -Path $FunctionCliXml -Force
                    # Starting HealthCheck Job
                    Write-Log "Starting HealthCheck Process" -AdditionalFields @($route_maintenance.RouteName)
                    Start-Job -Name $route_maintenance.RouteName -FilePath "$installDir\WinBGP-HealthCheck.ps1" -ArgumentList $route_maintenance
                  }
                  else {
                    Write-Log "Route '$($route_maintenance.RouteName)' was not in maintenance mode" -Level Warning
                  }
                }
              $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
              }
              elseif ($message -eq 'restart api') {
                # Log
                Write-Log "Restarting API engine"
                # Stop Api
                Stop-API
                # Start Api
                Start-API -ApiConfiguration $configuration.api
                # Start another thread waiting for control messages
                $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
              }
              elseif (($message -ne "stop") -and ($message -ne "suspend")) { # Start another thread waiting for control messages
                $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
              }
            }
            "Failed" {
              # Getting Errors
              $err = Receive-PipeHandlerThread $pipeThread
              Write-Log -Message "$source thread failed: $err" -Level Error
              Start-Sleep 1 # Avoid getting too many errors
              $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage" # Retry
            }
          }
        }
        "TimerTick" { # Example. Periodic event generated for this example
          # Watchdog
          # Read PowerShell jobs (To optimize query)
          [Array]$ChildJobs=(Get-Job -ErrorAction SilentlyContinue -State Running).Name
          # API
          if ($configuration.global.Api) {
            if ($ChildJobs -notcontains 'API') {
              # Start API
              Write-Log "Restarting API engine (Watchdog)" -Level Warning
              Remove-Job -Name 'API' -Force -ErrorAction SilentlyContinue
              # Start API
              Start-API -ApiConfiguration $configuration.api
            }
          }
          ForEach ($route in $configuration.routes) {
            #Control route accouncement if maintenance is false
            if (!$maintenance.($route.RouteName)) {
              if ($ChildJobs -notcontains "$($route.RouteName)") {
                # Cleaning unhealthy HealthCheck
                Write-Log "Restarting HealthCheck Process (Watchdog)" -AdditionalFields @($route.RouteName) -Level Warning
                Remove-Job -Name $route.RouteName -Force -ErrorAction SilentlyContinue
                Start-Job -Name $route.RouteName -FilePath "$installDir\WinBGP-HealthCheck.ps1" -ArgumentList $route
              }
            }
          }
        }
        default { # Should not happen
          Write-Log -Message "Unexpected event from ${source}: $Message" -Level Warning
        }
      }
    } while (($message -ne 'stop') -and ($message -ne 'suspend'))

    # Logging (Set first letter to uppercase and add a 'p' is message is 'stop')
    Write-Log -Message "$((Get-Culture).TextInfo.ToTitleCase($message))$(if($message -eq 'stop'){'p'})ing WinBGP engine"

    # Stopping healthchecks
    Write-Log -Message "Stopping HealthCheck engine"
    ForEach ($route in $configuration.routes) {
      # Stopping HealthCheck Job
      Write-Log "Stopping HealthCheck Process" -AdditionalFields @($route.RouteName)
      Stop-Job -Name $route.RouteName -ErrorAction SilentlyContinue
      Remove-Job -Name $route.RouteName -Force -ErrorAction SilentlyContinue
    }

    # Stopping API
    if ($configuration.global.Api) {
      # Stop API
      Stop-API
    }

    # Stopping the service (not performed when suspending service to keep the BGP engine working)
    if ($message -eq 'stop') {
        # Stopping all routes
        Write-Log -Message "Stopping BGP routes"
        ForEach ($route in $configuration.routes) {
          # Unannounce the route from Json configuration if there is no route
          if ((Get-BgpCustomRoute).Network -contains "$($route.Network)") {
            Write-Log -Message "Stopping route '$($route.RouteName)'"
            # Call function to start BGP route
            Remove-BGP -Route $route
          }
        }
      # Remove BGP Peering
      Write-Log -Message "Stopping BGP"
      Get-BgpRoutingPolicy | Remove-BgpRoutingPolicy -Force
      Get-BgpPeer | Remove-BgpPeer -Force
      Remove-BgpRouter -Force
    }

    #Export the maintenance status (To be kept over a restart or a reboot)
    if ($maintenance.Count -gt 0) {
      $maintenance | Export-CliXml -Path $FunctionCliXml -Force
    }
    #Otherwise, ensure file doesn't exist
    else {
      Remove-Item -Path $FunctionCliXml -Force
    }

  } catch { # An exception occurred while runnning the service
    $msg = $_.Exception.Message
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Log -Message "Error at line ${line}: $msg" -Level Error
    Write-Log "Stopping $($serviceInternalName) process" -Level Error
    # Forcing stop process so service will know that process is not running (to avoid having service running without process)
    Stop-Process -Name $serviceInternalName -Force
  } finally { # Invoked in all cases: Exception or normally by -Stop
    # Cleanup the periodic timer used in the above example
    Unregister-Event -SourceIdentifier $timerName
    $timer.stop()
    ############### End of the service code example. ################
    # Terminate the control pipe handler thread
    Get-PSThread | Remove-PSThread # Remove all remaining threads
    # Flush all leftover events (There may be some that arrived after we exited the while event loop, but before we unregistered the events)
    $events = Get-Event | Remove-Event
    # Log a termination event, no matter what the cause is.
    Write-Log -Message "WinBGP Engine successfully stopped"
  }
  return
}
