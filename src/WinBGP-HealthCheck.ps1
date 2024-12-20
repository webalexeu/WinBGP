###############################################################################
#                                                                             #
#   Name            WinBGP-HealthCheck                                        #
#                                                                             #
#   Description     WinBGP Routes HealthCheck                                 #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#                                                                             #
#   Copyright       (c) 2024 Alexandre JARDON | Webalex System.               #
#                   All rights reserved.'                                     #
#   LicenseUri      https://github.com/webalexeu/winbgp/blob/master/LICENSE   #
#   ProjectUri      https://github.com/webalexeu/winbgp                       #
#                                                                             #
###############################################################################

#Requires -version 5.1

Param (
    $Route=$false
)

$scriptVersion = '1.2.1'

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

# IPC communication with WinBGP-Engine
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

function Send-RouteControl {
  param (
    [Parameter(Mandatory=$true)]
    [String]$RouteName,         # Route Name
    [Parameter(Mandatory=$true)]
    [String]$Control            # Control
  )
  $PipeStatus=$null
  # Performing Action
  try {
    # Temporary
    $pipeName='Service_WinBGP'
    $Message="route $($RouteName) $($Control)"
    Send-PipeMessage -PipeName $pipeName -Message $Message
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
}


if ($Route) {
  # Waiting for Pipe to be started before starting healtcheck (as healtcheck need the pipe to communicate)
  # Temporary
  $pipeName='Service_WinBGP'
  while([System.IO.Directory]::GetFiles("\\.\\pipe\\") -notcontains "\\.\\pipe\\$($pipeName)") {
    # Wait 1 seconds before checking again
    Start-Sleep -Seconds 1
  }
  Write-Log -Message "HealthCheck Process started" -AdditionalFields @($Route.RouteName)

  # Initialize variables
  $rise_counter = 0
  $fall_counter = 0

  # Start a periodic timer
  $timer = new-object System.Timers.Timer
  $timer.Interval = ($route.Interval * 1000) # Milliseconds
  $timer.AutoReset = $true # Make it fire repeatedly
  Register-ObjectEvent $timer -EventName Elapsed -SourceIdentifier 'Timer'
  $timer.start() # Must be stopped in the finally block

  # Start a watchdog timer
  $watchdog = new-object System.Timers.Timer
  $watchdog.Interval = (30 * 1000) # Milliseconds
  $watchdog.AutoReset = $true # Make it fire repeatedly
  Register-ObjectEvent $watchdog -EventName Elapsed -SourceIdentifier 'Watchdog'
  $watchdog.start() # Must be stopped in the finally block

  if ($Route.WithdrawOnDown) {
    $pos = ($Route.WithdrawOnDownCheck).IndexOf(":")
    $check_method = ($Route.WithdrawOnDownCheck).Substring(0, $pos)
    $check_name = ($Route.WithdrawOnDownCheck).Substring($pos+2)
    switch($check_method) {
        'service' {
            # Service check from Json configuration
            $check_expression="if ((Get-Service $check_name).Status -eq 'Running') {return `$true} else {return `$false}"
        }
        'process' {
            # Process check from Json configuration
            $check_expression="if ((Get-Process -ProcessName $check_name -ErrorAction SilentlyContinue).count -ge '1') {return `$true} else {return `$false}"
        }
        'tcp' {
            # TCP port check from Json configuration
            $host_to_check=$check_name.split(":")[0]
            $port_to_check=$check_name.split(":")[1]
            $check_expression="if ((Test-NetConnection $host_to_check -Port $port_to_check).tcptestsucceeded) {return `$true} else {return `$false}"
        }
        'cluster' {
            # Cluster resource check from Json configuration
            $check_expression="if ((Get-ClusterNode -Name `"$env:COMPUTERNAME`" -ErrorAction SilentlyContinue | Get-ClusterResource -Name `"$check_name`" -ErrorAction SilentlyContinue).State -eq 'Online') {return `$true} else {return `$false}"
        }
        'custom' {
            # Custom check from Json configuration [Return status should be a Boolean (mandatory)]
            $check_expression=$check_name
            # Rewrite $check_name for logging
            $check_name='check'
        }
    }
  $check_method_name=(Get-Culture).textinfo.totitlecase($check_method.tolower())
  $check_log_output="$check_method_name '$check_name'"
  } else {
    $check_log_output='WithdrawOnDown not enabled'
    # Bypass Rise counter
    $rise_counter=$Route.Rise
    $rise_counter--
  }

  do {
      $timer_event = Wait-Event # Wait for the next incoming event
      if ($Route.WithdrawOnDown) {
        # Default status is false
        [bool]$check_status=$false
        # Performing check
        $check_status=Invoke-Expression -Command $check_expression
      } else {
        # Check always true as there is no check to perform
        [bool]$check_status=$true
      }
      # Depending on the timer source
      switch ($timer_event.SourceIdentifier) {
        'Timer' {
          # If check is OK
          if ($check_status) {
            # Create status log
            if ($Route.WithdrawOnDown) {
              $check_status_output="$check_log_output UP"
            } else {
              $check_status_output=$check_log_output
            }
            # Increment counter
            $rise_counter++
            # Waiting for rise threshold
            if ($rise_counter -ge $Route.Rise) {
                # Reset counter (only when rise has been reached)
                $fall_counter=0
                # Only when threshold is reached (Only once)
                if ($rise_counter -eq $Route.Rise) {
                    # If route already announced
                    if ((Get-BgpCustomRoute).Network -contains "$($Route.Network)") {
                        Write-Log -Message "$check_status_output - Route already started" -AdditionalFields @($Route.RouteName)
                    } else {
                        if ($Route.WithdrawOnDown) {
                          Write-Log -Message "$check_status_output - Rise threshold reached" -AdditionalFields @($Route.RouteName)
                        }
                        Write-Log -Message "$check_status_output - Trigger route start" -AdditionalFields @($Route.RouteName)
                        # Call function to start BGP route
                        $output=Send-RouteControl -RouteName $Route.RouteName -Control 'start'
                        if ($output -ne 'Success') {
                            $rise_counter--
                            Write-Log -Message "Route start error - Trigger retry" -AdditionalFields @($Route.RouteName) -Level Error
                        }
                    }
                }
            } else {
                Write-Log -Message "$check_status_output - Rise attempt: $rise_counter (Threshold: $($Route.Rise))" -AdditionalFields @($Route.RouteName)
            }
        #     If check fail
          } else {
            # Create status log
            if ($Route.WithdrawOnDown) {
              $check_status_output="$check_log_output DOWN"
            } else {
              $check_status_output=$check_log_output
            }
            # Increment counter
            $fall_counter++
            # Waiting for fall threshold
            if ($fall_counter -ge $Route.Fall) {
                # Reset counter (only when fall has been reached)
                $rise_counter=0
                # Only when threshold is reached (Only once)
                if ($fall_counter -eq $Route.Fall) {
                    # If route already unannounced
                    if ((Get-BgpCustomRoute).Network -notcontains "$($Route.Network)") {
                        Write-Log -Message "$check_status_output - Route already stopped" -AdditionalFields @($Route.RouteName)
                    } else {
                        if ($Route.WithdrawOnDown) {
                          Write-Log -Message "$check_status_output - Fall threshold reached" -AdditionalFields @($Route.RouteName)
                        }
                        Write-Log -Message "$check_status_output - Trigger route stop" -AdditionalFields @($Route.RouteName)
                        # Call function to stop BGP route
                        $output=Send-RouteControl -RouteName $Route.RouteName -Control 'stop'
                        if ($output -ne 'Success') {
                            $fall_counter--
                            Write-Log -Message "Route stop error - Trigger retry" -AdditionalFields @($Route.RouteName) -Level Error
                        }
                    }
                }
            } else {
                Write-Log -Message "$check_status_output - Fall attempt: $fall_counter (Threshold: $($Route.Fall))" -AdditionalFields @($Route.RouteName)
            }
          }
        }
        'Watchdog' {
          # If check is OK
          if ($check_status) {
            # Waiting for rise threshold
            if ($rise_counter -gt $Route.Rise) {
              # Announce the route from Json configuration if there is no route
              if ((Get-BgpCustomRoute).Network -notcontains "$($Route.Network)")
              {
                  Write-Log -Message "$check_status_output but route not started - Trigger route start (Watchdog)" -AdditionalFields @($Route.RouteName) -Level Warning
                  # Call function to start BGP route
                  $output=Send-RouteControl -RouteName $Route.RouteName -Control 'start'
                  if ($output -ne 'Success') {
                    Write-Log -Message "Route start error" -AdditionalFields @($Route.RouteName) -Level Error
                  }
              } else {
                  # Checking IP is mounted properly
                  if($route.DynamicIpSetup) {
                      if (!(Get-NetIPAddress -IPAddress "$($route.Network.split('/')[0])")) {
                          Write-Log "Route announced but IP Address not mounted (Watchdog)" -AdditionalFields @($route.RouteName) -Level Warning
                          Add-IP $route
                      }
                  }
              }
            }
          # If check fail
          } else {
            # Waiting for fall threshold
            if ($fall_counter -gt $Route.Fall) {
              # Stop Announce the route from Json configuration
              if ((Get-BgpCustomRoute).Network -contains "$($Route.Network)")
              {
                Write-Log -Message "$check_status_output but route not stopped - Trigger route stop (Watchdog)" -AdditionalFields @($Route.RouteName)
                # Call function to remove BGP route
                $output=Send-RouteControl -RouteName $Route.RouteName -Control 'stop'
                if ($output -ne 'Success') {
                  Write-Log -Message "Route stop error" -AdditionalFields @($Route.RouteName) -Level Error
                }
              } else {
                # Checking IP is mounted properly
                if($route.DynamicIpSetup) {
                    if (Get-NetIPAddress -IPAddress "$($route.Network.split('/')[0])") {
                        Write-Log "Route not announced but IP Address still mounted (Watchdog)" -AdditionalFields @($route.RouteName) -Level Warning
                        Remove-IP $route
                    }
                }
              }
            }
          }
        }
      }
      $timer_event | Remove-Event # Flush the event from the queue
  } while ($message -ne "exit")

  # Stopping timers
  $timer.stop()
  $watchdog.stop()
} else {
  $OutputVersion=@{
    'Version'=$scriptVersion
  }
  return $OutputVersion
}
