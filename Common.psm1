function Set-IPConfiguration {
  [CmdletBinding(
    DefaultParameterSetName = 'Not Targeted',
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory=$true
    )]
    [ipaddress]
    $IPAddress,

    [Parameter(
      Mandatory=$true
    )]
    [byte]
    $PrefixLength,
    
    [ipaddress]
    $DefaultGateway,
    
    [ipaddress[]]
    $DNSAddresses,

    [Parameter(
      ParameterSetName = 'Not Targeted'
    )]
    [Parameter(
      ParameterSetName = 'TargetByDhcp'
    )]
    [Parameter(
      ParameterSetName = 'TargetByNoDhcp'
    )]
    [switch]
    $AnyAdapter,

    [Parameter(
      ParameterSetName = 'TargetByNeighbor'
    )]
    [string]
    $TargetByNeighbor,

    [Parameter(
      ParameterSetName = 'TargetByDhcp'
    )]
    [switch]
    $TargetByDhcp,

    [Parameter(
      ParameterSetName = 'TargetByNoDhcp'
    )]
    [switch]
    $TargetByNoDhcp
  )

  if ($PSCmdlet.ParameterSetName -eq 'Not Targeted') {
    $adapterIndexes = Get-NetAdapter |
                        ForEach-Object ifIndex

    $ifIndex = @(
      Get-NetIPInterface -InterfaceIndex $adapterIndexes `
                         -AddressFamily IPv4 `
                         -Dhcp Enabled |
        ForEach-Object ifIndex
    )
  }
  elseif ($PSCmdlet.ParameterSetName -eq "TargetByNeighbor") {
    $pingObj = New-Object System.Net.NetworkInformation.Ping

    for ($a = 0; $a -lt 4; $a++) {
      try {
        $replyAddress = $pingObj.Send($TargetByNeighbor) |
                          ForEach-Object Address |
                          ForEach-Object ToString
      } catch {
        $Global:Error.RemoveAt(0)

        $replyAddress = $null
      }

      if ($replyAddress -is [String]) {
        break
      }
    }

    if ($replyAddress -isnot [String]) {
      Write-Error "Unable to ping (TargetBy) Neighbor '$TargetByNeighbor'."
      return
    }

    # Looped to provide redundancy, as NetNeighbor data will occasionally
    # require time to populate after ping.
    for ($a = 0; $a -lt 4; $a++) {
      $ifIndex = @(
        Get-NetNeighbor |
          Where-Object IPAddress -eq $replyAddress |
          Where-Object State -ne Unreachable |
          ForEach-Object ifIndex
      )

      if ($ifIndex.Count -gt 0) {
        break
      }

      Start-Sleep -Seconds 1
    }

    if ($ifIndex.Count -eq 0) {
      Write-Error "Unable to derive interface for (TargetBy) Neighbor '$TargetByNeighbor' with address '$replyAddress'."
      return
    }
  }
  elseif ($PSCmdlet.ParameterSetName -eq "TargetByDhcp") {
    $ifIndex = @(
      Get-NetAdapter |
        Where-Object Status -eq Up |
        Where-Object {
          $addr = $_ |
                    Get-NetIPAddress -AddressFamily IPv4 |
                    ForEach-Object IPAddress
                   
          $addr -notlike "169.254.*"
        } |
        ForEach-Object ifIndex
    )
  }
  elseif ($PSCmdlet.ParameterSetName -eq "TargetByNoDhcp") {
    $ifIndex = @(
      Get-NetAdapter |
        Where-Object Status -eq Up |
        Where-Object {
          $addr = $_ |
                    Get-NetIPAddress -AddressFamily IPv4 |
                    ForEach-Object IPAddress
                   
          $addr -like "169.254.*"
        } |
        ForEach-Object ifIndex
    )
  }

  if ($ifIndex.Count -gt 1 -and (-not $AnyAdapter)) {
    Write-Error "The IP Interface to which to assign the provided configuration is ambiguous. Use a means of targeting (e.g. -TargetByNeighbor), or use the -AnyAdapter switch to specify that the configuration may be assigned to any interface."
    return
  }

  if ($ifIndex.Count -eq 0) {
    Write-Error "No non-static IP Interface to which to assign the provided configuration was found."
    return
  }

  $ifIndex = $ifIndex |
               Select-Object -First 1

  Set-NetIPInterface -InterfaceIndex $ifIndex `
                     -AddressFamily IPv4 `
                     -Dhcp Disabled

  $params = @{
    InterfaceIndex = $ifIndex
    IPAddress      = $IPAddress.ToString()
    AddressFamily  = "IPv4"
    Type           = "Unicast"
    PrefixLength   = $PrefixLength
  }

  if ($DefaultGateway -ne $null) {
    $params.DefaultGateway = $DefaultGateway.ToString()
  }

  New-NetIPAddress @params | Out-Null

  if ($DNSAddresses -ne $null) {
    Set-DnsClientServerAddress -InterfaceIndex $ifIndex `
                               -ServerAddresses ($DNSAddresses | ForEach-Object ToString)
  }
}

function Wait-Domain {
  [CmdletBinding()]
  param(
    [timespan]
    $Timeout = [timespan]::FromMinutes(10)
  )

  try {
    $span = Measure-Command {
      $start = [datetime]::Now

      while ($true) {
        if (([datetime]::Now - $start) -gt $Timeout.Duration()) {
          throw "Module import w/ 'AD' PSDrive in out-of-process PSJob did not occur within configured timeout."
        }

        $job = Start-Job -ScriptBlock {
          Import-Module ActiveDirectory -ErrorAction Stop

          Get-PSDrive -Name AD -ErrorAction Stop
        }
      
        $job |
          Wait-Job |
          Out-Null
      
        $jobState = $job.ChildJobs[0].JobStateInfo
      
        $job |
          Remove-Job
      
        if (
          $jobState.State -eq [System.Management.Automation.JobState]::Failed -and
          $jobState.Reason.Message -eq "Attempting to perform the InitializeDefaultDrives operation on the 'ActiveDirectory' provider failed."
        ) {
          continue
        } elseif (
          $jobState.State -eq [System.Management.Automation.JobState]::Failed -and
          $jobState.Reason.Message -eq "Cannot find drive. A drive with the name 'AD' does not exist."
        ) {
          continue
        } elseif ($jobState.State -ne [System.Management.Automation.JobState]::Completed) {
          throw $jobState.Reason
        } else {
          break
        }
      }
    }

    Write-Verbose "Spent $span waiting for successful module import w/ PSDrive in out-of-process PSJob."

    Import-Module ActiveDirectory -Verbose:$false -ErrorAction Stop

    Get-PSDrive -Name AD -ErrorAction Stop |
      Out-Null

    Write-Verbose "Confirmed successful module import w/ PSDrive in-process."

  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Join-Domain {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $DomainName,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $UserName,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Password,

    [string]
    $OUPath,

    [timespan]
    $Timeout = [timespan]::FromMinutes(4)
  )
  try {
    $start = [datetime]::Now

    $ping = New-Object System.Net.NetworkInformation.Ping

    while ($true) {
      if (([datetime]::Now - $start) -gt $Timeout.Duration()) {
        throw "Domain join failed: the domain name was not ping-accessible within the configured timeout."
      }

      try {
        $pingResult = $ping.Send($DomainName)
      } catch {
        if (
          $_.Exception -is [System.Management.Automation.MethodInvocationException] -and
          $_.Exception.InnerException -is [System.Net.NetworkInformation.PingException] -and
          $_.Exception.InnerException.InnerException -is [System.Net.Sockets.SocketException] -and
          $_.Exception.InnerException.InnerException.Message -eq "No such host is known"
        ) {
          $Global:Error.RemoveAt(0)

          & ipconfig /flushdns |
            Out-Null
        } else {
          throw "Domain join failed: ping attempt failed with unexpected exception: $($_.Exception.Message)"
        }
      }

      if (
        $null -ne $pingResult -and
        $pingResult.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
      ) {
        break
      }
    }

    $joinCredential = New-Object System.Management.Automation.PSCredential @(
      $UserName,
      (ConvertTo-SecureString -String $Password -AsPlainText -Force)
    )

    $addParams = @{
      DomainName  = $DomainName
      Credential  = $joinCredential
      ErrorAction = "Stop"
      PassThru    = $true
    }

    if ($PSBoundParameters.ContainsKey("OUPath")) {
      $addParams.OUPath = $OUPath
    }

    while ($true) {
      if (([datetime]::Now - $start) -gt $Timeout.Duration()) {
        throw "Domain join failed: the add operation did not succeed within the configured timeout."
      }

      try {
        $addResult = Add-Computer @addParams
      } catch {
        if ($_.Exception.Message -eq "%PLACEHOLDER%") { # Placeholder; expected avenues of join failure would be enumerated here.
          $Global:Error.RemoveAt(0)          
        } else {
          throw "Domain join failed: join attempt failed with unexpected exception: $($_.Exception.Message)"
        }
      }

      if ($null -ne $addResult -and $addResult.HasSucceeded -eq $true) {
        break
      }
    }
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

$sessions = @{}

function New-PSSessionWithModules ([string[]]$SessionNames, [string]$ComputerNamePrefix) {
  foreach ($name in $SessionNames) {
    $computerName = $ComputerNamePrefix + $name

    $script:sessions.$name = New-PSSession -ComputerName $computerName

    Invoke-Command -Session $script:sessions.$name -ScriptBlock {
      . C:\CT\Modules\import.ps1
    }
  }
}

function Remove-PSSessionWithModules {
  $script:sessions.GetEnumerator() |
    ForEach-Object {
      $_.Value |
        Remove-PSSession
    }
}

function Disable-LocalUsers ([string[]]$Users) {
  $hostname = [System.Net.Dns]::GetHostName()

  if ($Users -eq $null) {

    # Even *before* a restart after joining a domain, the names of domain users
    # are queryable through WMI. Thus, the results must be filtered by hostname
    # as well as disabled state to return -only- those for which localhost is
    # the authority.

    $Users = [string[]]@(
      Get-CimInstance -ClassName Win32_UserAccount `
                      -Filter "Domain = `"$hostname`" AND Disabled != True" |
        ForEach-Object Name
    )
  }

  foreach ($user in $Users) {
    $userObj = [ADSI]"WinNT://$hostname/$user"
    $userObj.UserFlags = $userObj.UserFlags.Value -bor 2 # Add the "Disabled" flag to the bitmask.
    $userObj.SetInfo() # Make it stick.
  }
}

function Set-AutoLogon {
  [CmdletBinding(
    DefaultParameterSetName = "Count"
  )]
  param(
    [string]
    $DomainName = "",
    
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $UserName,

    [Parameter(
      Mandatory = $true
    )]    
    [string]
    $Password,

    [Parameter(
      ParameterSetName = "Count"
    )]
    [byte]
    $Count = 1,

    [Parameter(
      ParameterSetName = "Persist",
      Mandatory = $true
    )]
    [switch]
    $Persist,

    [Parameter(
      ParameterSetName = "Force",
      Mandatory = $true
    )]
    [switch]
    $Force
  )
  $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

  Set-ItemProperty -LiteralPath $path -Name AutoAdminLogon    -Value "1"         -Force
  Set-ItemProperty -LiteralPath $path -Name DefaultDomainName -Value $DomainName -Force
  Set-ItemProperty -LiteralPath $path -Name DefaultUserName   -Value $UserName   -Force
  Set-ItemProperty -LiteralPath $path -Name DefaultPassword   -Value $Password   -Force

  if ($PSCmdlet.ParameterSetName -eq "Count") {
    Set-ItemProperty -LiteralPath $path -Name AutoLogonCount -Value $Count -Type DWord -Force
  } elseif ((Get-Item -LiteralPath $path).Property -contains "AutoLogonCount") {
    Remove-ItemProperty -LiteralPath $path -Name AutoLogonCount -Force
  }

  if ($PSCmdlet.ParameterSetName -eq "Force") {
    Set-ItemProperty -LiteralPath $path -Name ForceAutoLogon -Value 1 -Type DWord -Force
  }
}

# PROVISO: If an active user account with a blank password has been set to
# autologon, clearing it in this manner will not actually stop the account
# from logging on at every reboot. There is no available remediation.
function Clear-AutoLogon {
  $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

  Set-ItemProperty -LiteralPath $path -Name AutoAdminLogon -Value "0" -Force

  $propertiesAtPath = Get-Item -LiteralPath $path |
                        ForEach-Object Property

  "DefaultPassword",
  "AutoLogonCount",
  "ForceAutoLogon" |
    ForEach-Object {
      if ($propertiesAtPath -contains $_) {
        Remove-ItemProperty -LiteralPath $path -Name $_ -Force
      }
    }
}

function Set-VolumeDriveLetter {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $FileSystemLabel,

    [char]
    $DriveLetter,

    [timespan]
    $Timeout = [timespan]::FromMinutes(1),

    [switch]
    $OnlineAllDisks,

    [switch]
    $PassThru
  )

  try {
    $startTime = [datetime]::Now

    if ($PSBoundParameters.ContainsKey("DriveLetter") -and $DriveLetter -cnotmatch "^[A-Z]$") {
      throw "When provided, DriveLetter must be a capital letter."
    }

    $volume = @(
      Get-Volume |
        Where-Object FileSystemLabel -ceq $FileSystemLabel
    )

    Write-Verbose "Initial volume-with-label count: $($volume.Count)."

    if ($volume.Count -eq 0) {

      Write-Verbose "Volume not found w/ initial search; onlining offline disk(s)."

      $offlineDisks = @(
        Get-Disk |
          Where-Object OperationalStatus -eq Offline |
          Where-Object PartitionStyle -ne RAW
      )

      Write-Verbose "Offline disks count: $($offlineDisks.Count)."

      if ($offlineDisks.Count -gt 1 -and $OnlineAllDisks -eq $false) {
        throw "More than one attached partitioned disk is offline. Use the OnlineAllDisks switch to bring all disks online."
      }

      $offlineDisks |
        Set-Disk -IsOffline:$false

      $offlineDisks |
        Set-Disk -IsReadOnly:$false

      $volume = @(
        Get-Volume |
          Where-Object FileSystemLabel -ceq $FileSystemLabel
      )

      Write-Verbose "Subsequent volume-with-label count: $($volume.Count)."
    }

    if ($volume.Count -ne 1) {
      throw "Exactly one volume with FileSystemLabel provided must be found on attached storage. $($volume.Count) were found."
    }

    $partition = $volume |
                   Get-Partition

    if ([byte]$partition.DriveLetter -eq 0 -or ($PSBoundParameters.ContainsKey("DriveLetter") -and $partition.DriveLetter -cne $DriveLetter)) {
      Write-Verbose "Volume partition drive letter is unassigned or not as desired."

      Write-Verbose "  - Changing."

      if ($PSBoundParameters.ContainsKey("DriveLetter")) {
        $partition |
          Set-Partition -NewDriveLetter $DriveLetter
      } else {
        $partition |
          Add-PartitionAccessPath -AssignDriveLetter
      }

      Write-Verbose "  - Confirming change has taken effect @ $([datetime]::Now - $startTime)."

      do {
        if (([datetime]::Now - $startTime) -gt $Timeout) {
          throw "Volume partition drive letter change was not confirmed within configured timeout."
        }

        $partition = $partition |
                       Get-Partition
      } until (
        [byte]$partition.DriveLetter -ne 0 -and
        ($PSBoundParameters.ContainsKey("DriveLetter") -eq $false -or $partition.DriveLetter -eq $DriveLetter)
      )

      Write-Verbose "  - Change confirmed @ $([datetime]::Now - $startTime)."
    }

    $volume = Get-Volume -UniqueId $volume[0].UniqueId

    $volume | Add-Member -MemberType NoteProperty -Name Root -Value "$($volume.DriveLetter):\"

    Write-Verbose "Confirming PSDrive availability of Volume.Root @ $([datetime]::Now - $startTime)."

    do {
      if (([datetime]::Now - $startTime) -gt $Timeout) {
        throw "PSDrive availability was not confirmed within configured timeout."
      }
    } until ($null -ne (Get-PSDrive | Where-Object Root -eq $volume.Root))

    Write-Verbose "PSDrive availability of Volume.Root confirmed @ $([datetime]::Now - $startTime)."

    if ($PassThru) {
      Write-Verbose "Emitting Volume object. Root is available at Volume.Root to facilitate pathing."
      $volume
    }
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

#region CTBackInfo
function Test-CTBackInfo ([switch]$Quiet) {
  function Test-OperatingSystemHasGUI {
    $serverLevelsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels"

    if (-not (Test-Path -LiteralPath $serverLevelsPath)) {
      return $true
    }

    $serverLevels = Get-Item -LiteralPath $serverLevelsPath

    if (
          $serverLevels.Property -notcontains "ServerCore" `
      -or $serverLevels.GetValue("ServerCore") -ne 1
    ) {
      return $true
    }

    if (
          $serverLevels.Property -contains "Server-Gui-Mgmt" `
      -or $serverLevels.Property -contains "Server-Gui-Shell"
    ) {
      return $true
    }

    return $false
  }

  $outHash = @{
    OSHasGUI       = Test-OperatingSystemHasGUI
  }

  if ($Quiet) {
    return $outHash.Values -notcontains $false
  }
  else {
    return [PSCustomObject]$outHash
  }
}

function New-CTBackInfoUserListObjectsItem {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [string]
    $DomainName = "",
    
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $UserName,

    [Parameter(
      Mandatory = $true
    )]    
    [string]
    $Password
  )

  [PSCustomObject]@{
    PSTypeName = "CTBackInfoUserListObjectsItem"
    DomainName = $DomainName
    UserName   = $UserName
    Password   = $Password
  }
}

Set-Alias -Name ulItem -Value New-CTBackInfoUserListObjectsItem
#endregion

#region Saved Data
$dataPath = Join-Path -Path $PSScriptRoot -ChildPath savedData.json

# TODO: Code a means of retrieving data from another computer using the C$
# share.
function Get-SavedData {
  $data = @{}

  if (Test-Path -LiteralPath $script:dataPath -PathType Leaf) {
    $obj = Get-Content -LiteralPath $script:dataPath -Raw |
             ConvertFrom-Json

    foreach ($property in $obj.psobject.Properties) {
      $data.($property.Name) = $property.Value
    }
  }

  return $data
}

function Set-SavedData ($data) {
  if ($data -isnot [hashtable]) {
    Write-Error "Saved Data must be in the form of a [hashtable]."
  }

  $keyNotStringCount = @(
    $data.Keys |
      Where-Object {$_ -isnot [string]}
  ).Count

  $valueNotStringCount = @(
    $data.Values |
      Where-Object {$_ -isnot [string]}
  ).Count

  if (($keyNotStringCount + $valueNotStringCount) -gt 0) {
    Write-Error "Saved Data must be in the form of a [hashtable] association of [string] keys with [string] values."
  }

  $json = ([PSCustomObject]$data) | ConvertTo-Json -Compress

  New-Item -Path $script:dataPath -ItemType File -Value $json -Force | Out-Null
}


# The ConvertFrom-Json cmdlet is unavailable in PowerShell -lt v3.
$scriptParameters = $null
if ((Test-Path -LiteralPath $PSScriptRoot\ScriptParameters.json) -and $PSVersionTable.PSVersion -gt "2.0") {
  $scriptParameters = Get-Content -LiteralPath $PSScriptRoot\ScriptParameters.json -Raw |
                        ConvertFrom-Json
}


#endregion

function Write-TokenSubstitutions {
  [CmdletBinding(
    PositionalBinding=$false
  )]
  param(
    [Parameter(
      ParameterSetName = 'String',
      Mandatory = $true
    )]
    [String]
    $String,

    [Parameter(
      ParameterSetName = 'LiteralPath',
      Mandatory = $true
    )]
    [String]
    $LiteralPath,

    [Parameter(
      Mandatory = $true
    )]
    [Hashtable]
    $Substitutions
  )

  function Sub_String ($String, $Substitutions) {
    foreach ($key in $Substitutions.Keys) {
      $token = "%$($key.ToUpper())%"

      if ($String.IndexOf($token) -lt 0) {
        continue
      }

      Set-Variable -Scope 1 -Name stringWasModded -Value $true

      $String = $String.Replace($token, $Substitutions.$key)
    }

    $String
  }

  if ($PSCmdlet.ParameterSetName -eq "String") {
    return Sub_String $String $Substitutions
  }

  if (-not (Test-Path -LiteralPath $LiteralPath)) {
    Write-Error "No item was found at the LiteralPath provided."
    return
  }

  $subItem = Get-Item -LiteralPath $LiteralPath

  if ($subItem -is [IO.FileInfo]) {
    $subTargets = @(
      $subItem.FullName
    )
  }
  elseif ($subItem -is [IO.DirectoryInfo]) {
    $subTargets = @(
      Get-ChildItem -LiteralPath $LiteralPath -File -Force -Recurse |
        ForEach-Object FullName
    )
  }
  else {
    Write-Error "LiteralPath must be that of a file or directory on a filesystem drive."
    return
  }

  foreach ($target in $subTargets) {
    $targetString = Get-Content -LiteralPath $target -Raw

    $stringWasModded = $false

    $targetString = Sub_String $targetString $Substitutions

    if ($stringWasModded) {
      Set-Content -LiteralPath $target -Value $targetString
    }
  }
}

function Invoke-ConfigTaskAsUser {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      ValueFromPipeline = $true,
      Mandatory = $true      
    )]
    [ciminstance]
    $InputObject,

    [Parameter(
      Mandatory = $true      
    )]
    [string]
    $UserName,

    [Parameter(
      Mandatory = $true      
    )]
    [string]
    $Password,

    [timespan]
    $Timeout = [timespan]::FromMinutes(1)
  )
  begin {
    try {
      $start = [datetime]::Now

      while ($true) {
        if (([datetime]::Now - $start) -gt $Timeout.Duration()) {
          throw "Invoke failed: Translation from UserName to SID was not confirmed within the configured timeout."
        }
      
        try {
          $NTAccount = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $UserName

          $SID = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier])
        } catch {
          if ($_.Exception.Message -eq "Placeholder for known exception(s).") {
            $Global:Error.RemoveAt(0)
          } else {
            throw "Invoke failed: translation from UserName to SID failed with unexpected exception: $($_.Exception.Message)"
          }
        }

        if ($null -ne $SID -and $SID -is [System.Security.Principal.SecurityIdentifier]) {
          break
        }
      }
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
  process {
    try {
      if ($InputObject.CimClass.ToString() -ne "Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask") {
        throw "InputObject must be a ciminstance of class MSFT_ScheduledTask."
      }

      while ($true) {
        if (([datetime]::Now - $start) -gt $Timeout.Duration()) {
          throw "Invoke failed: Scheduled task changes were not successful within the configured timeout."
        }
      
        try {
          Set-ScheduledTask `
          -TaskName $InputObject.TaskName `
          -User $UserName `
          -Password $Password `
          -Trigger (New-ScheduledTaskTrigger -At (Get-Date).AddMinutes(1) -Once) `
          -ErrorAction Stop

          $hadError = $false
        } catch {
          $hadError = $true

          if (
            $_.Exception -is [Microsoft.Management.Infrastructure.CimException] -and
            $_.Exception.Message -eq "The user name or password is incorrect.`r`n"
          ) {
            $Global:Error.RemoveAt(0)
          } else {
            throw "Invoke failed: 'Set-ScheduledTask' failed with unexpected exception: $($_.Exception.Message)"
          }
        }

        if (-not $hadError) {
          break
        }
      }
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}

function Register-ConfigTask ([string]$Name, [scriptblock]$Task, [switch]$AtStartup, [switch]$NoAutoUnregister) {
  $stringTask = $Task.ToString().Trim()

  $unregisterBlock = {
    $inc = 1
    while ($true) {
      try {
        Unregister-ScheduledTask -TaskName "%NAME%" -Confirm:$false -ErrorAction Stop
        break
      } catch {
        if ($inc -le 5) {
          $Global:Error.RemoveAt(0)

          Start-Sleep -Seconds 60
          $inc++
        }
        else {
          Write-Error "Redundant wrapping of `"Unregister-ScheduledTask`" for Task Name `"%NAME%`" failed on $inc consecutive occasions over ~$inc minutes."
          break
        }
      }
    }
  }.ToString().Trim().Replace("%NAME%", $Name)

  if (-not ($NoAutoUnregister)) {
    $stringTask = $unregisterBlock + ([System.Environment]::NewLine * 2) + $stringTask
  }

  $encodedCommand = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes($stringTask)
  )

  $action = New-ScheduledTaskAction -Execute "$env:SystemDrive\Windows\System32\WindowsPowershell\v1.0\powershell.exe" `
                                    -Argument "/NonInteractive /EncodedCommand $encodedCommand"

  $params = @{
    TaskName = $Name
    User     = "NT AUTHORITY\SYSTEM"
    Action   = $action
    Settings = New-ScheduledTaskSettingsSet -Priority 5 # Normal priority; 20% faster than default of 7.
  }
  
  if ($AtStartup) {
    $params.Trigger = New-ScheduledTaskTrigger -AtStartup
  }

  $taskObj = Register-ScheduledTask @params

  if ($params.Keys -contains "Trigger") {
    $taskObj | Disable-ScheduledTask | Out-Null
  }
}

function Register-LogonTask ([string]$For, [string]$Name,  [scriptblock]$Task, [switch]$NoAutoUnregister) {
  $stringTask = $Task.ToString().Trim()

  $unregisterBlock = {
    $inc = 1
    while ($true) {
      try {
        Unregister-ScheduledTask -TaskName "%NAME%" -Confirm:$false -ErrorAction Stop
        break
      } catch {
        if ($inc -le 5) {
          $Global:Error.RemoveAt(0)

          Start-Sleep -Seconds 60
          $inc++
        }
        else {
          Write-Error "Redundant wrapping of `"Unregister-ScheduledTask`" for Task Name `"%NAME%`" failed on $inc consecutive occasions over ~$inc minutes."
          break
        }
      }
    }
  }.ToString().Trim().Replace("%NAME%", $Name)

  if (-not ($NoAutoUnregister)) {
    $stringTask = $unregisterBlock + ([System.Environment]::NewLine * 2) + $stringTask
  }

  $encodedCommand = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes($stringTask)
  )

  # Security Descriptor should give unelevated users READ, EXECUTE, and DELETE
  # permissions.
  $xml = @'
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <SecurityDescriptor>D:P(A;;0x1300a9;;;BU)(A;;FA;;;BA)(A;;FA;;;SY)</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <UserId />
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId />
    </Principal>
  </Principals>
  <Settings>
    <Priority>5</Priority>
  </Settings>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments />
    </Exec>
  </Actions>
</Task>
'@ -as [xml]

  $xml.Task.Triggers.LogonTrigger.UserId = $For
  $xml.Task.Principals.Principal.UserId = $For
  $xml.Task.Actions.Exec.Arguments = "/NoLogo /NoProfile /NonInteractive /EncodedCommand $encodedCommand"

  Register-ScheduledTask -TaskName $Name -Xml $xml.OuterXml
}

#region Cleanup & Host Communication
function Remove-ItemRobust {
  [CmdletBinding()]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true
    )]
    [Alias("PSPath")]
    [string]
    $LiteralPath,

    [switch]
    $Recurse,

    [timespan]
    $Timeout = [timespan]::FromMinutes(1)
  )
  begin {
    $start = [datetime]::Now

    $riParams = @{
      LiteralPath = $null
      Recurse     = $Recurse
      Force       = $true
      ErrorAction = "Stop"
    }
  }
  process {
    try {
      $riParams.LiteralPath = $LiteralPath

      do {
        if (([datetime]::Now - $start) -gt $Timeout) {
          throw "Removal of item was not confirmed within configured timeout."
        }

        try {
          $pathMayExist = Test-Path -LiteralPath $riParams.LiteralPath -ErrorAction Stop

          if ($pathMayExist) {
            Remove-Item @riParams

            Write-Verbose "The 'Remove-Item' command for path '$($riParams.LiteralPath)' finished without error @ $([datetime]::Now - $start)."
          } else {
            Write-Verbose "Absence of item @ path '$($riParams.LiteralPath)' confirmed @ $([datetime]::Now - $start)."
          }
        } catch {
          $Global:Error.RemoveAt(0)

          $pathMayExist = $true
        }
      } until (-not $pathMayExist)
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}

function Remove-SetupPaths ([string[]]$And = @()) {
  $paths = @(
    "unattend.xml"                 # Unattend file placed by LoadBuilder for OS specialization.
    "Windows\Panther\unattend.xml" # Unattend file cached by Windows Setup.
    "CT"                           # Packages, Modules, and other OS specialization resources.
    "Packages"                     # Legacy specialization resource path.
    "Logs"                         # "Junk" folder left behind after S2016 install.
  ) + $And

  $paths |
    ForEach-Object {
      $path = Join-Path -Path $env:SystemDrive -ChildPath $_

      if ((Get-Location).Path -like "$path*") {
        Set-Location (Join-Path -Path $env:SystemDrive -ChildPath "\")
      }

      do {
        try {
          $pathMayExist = Test-Path -LiteralPath $path -ErrorAction Stop

          if ($pathMayExist) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
          }
        } catch {
          $pathMayExist = $true

          $global:Error.RemoveAt(0)
          Start-Sleep -Seconds 10
        }
      } while ($pathMayExist)
    }
}

$errorLogPath = Join-Path -Path $env:SystemDrive -ChildPath Users\Public\Desktop\Errors.txt

function Write-ErrorLog {
  if (-not $global:Error) {
    return
  }

  if (Test-Path -LiteralPath $script:errorLogPath) {
    Add-Content -LiteralPath $script:errorLogPath -Value ([System.Environment]::NewLine + ("-" * 80) + [System.Environment]::NewLine)
  }

  $global:Error | Out-File -FilePath $script:errorLogPath -Append -Width ([int]::MaxValue)

  # Ensures that host-visible evidence of any error is written at the earliest
  # opportunity. Since an erroneous configuration is not one that is meant to
  # persist, this should have little to no impact on my processes.
  Invoke-FinAckHandshake
}

function Invoke-FinAckHandshake ([Switch]$RemoveHostValues) {
  $dataExchangePath = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine'

  $guestValues = Join-Path -Path $dataExchangePath -ChildPath Guest
  $hostValues  = Join-Path -Path $dataExchangePath -ChildPath External

   # Inform Host & Infinite Pause On Error Detection.
  if (Test-Path -LiteralPath $script:errorLogPath) {
    New-ItemProperty -LiteralPath $guestValues -Name err
    while ($true) {
      Start-Sleep -Milliseconds ([Int]::MaxValue)
    }
  }

  New-ItemProperty -LiteralPath $guestValues -Name fin

  do {

    Start-Sleep -Seconds 5

    $properties = Get-Item -LiteralPath $hostValues |
                    ForEach-Object {$_.Property} # An archaism needed to make this work in Windows 7.

  } while ($properties -notcontains 'ack')

  Remove-ItemProperty -LiteralPath $guestValues -Name fin

  if ($RemoveHostValues) {
    Start-Sleep -Seconds 10
    Remove-ItemProperty -LiteralPath $hostValues -Name ack
  }
}

function Write-FinFile {
  [PSCustomObject]@{
    "FIN Message" = @"
When this file is written to the public desktop, configuration has ended. If the error log file was not also written, the configuration is assumed to be successful.

Students, if you see this file it is safe to delete it -- although I really should have done so myself.
"@
    "FIN Time" = [datetime]::Now.ToString("O")
  } |
    Format-List |
    Out-File -FilePath (Join-Path -Path ([System.Environment]::GetFolderPath("CommonDesktop")) -ChildPath FIN.txt)
}

function Wait-HostPoke ([Switch]$RemoveHostValues) {
  $dataExchangePath = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine'

  $guestValues = Join-Path -Path $dataExchangePath -ChildPath Guest
  $hostValues  = Join-Path -Path $dataExchangePath -ChildPath External

  do {
    Start-Sleep -Seconds 60

    $properties = Get-Item -LiteralPath $hostValues |
                    ForEach-Object {$_.Property} # An archaism needed to make this work in Windows 7.

  } while ($properties -notcontains 'poke')

  New-ItemProperty -LiteralPath $guestValues -Name ack

  # Used where the Host OS is incapable of truly removing values written to the
  # guest via KVP exchange. The host will remove (and assume successful removal
  # of) the "poke" value a maximum of about 60 seconds after an "ack" has been
  # written. Hence, this function must wait at least that long before removal
  # to avoid "breaking" the handshake from the host's point of view. To be
  # safe, I have it wait a full three minutes.
  if ($RemoveHostValues) {
    Start-Sleep -Seconds 180
    Remove-ItemProperty -LiteralPath $hostValues -Name poke
  }

  do {

    Start-Sleep -Seconds 5

    $properties = Get-Item -LiteralPath $hostValues |
                    ForEach-Object {$_.Property} # An archaism needed to make this work in Windows 7.

  } while ($properties -contains 'poke')

  Remove-ItemProperty -LiteralPath $guestValues -Name ack
}
#endregion

Export-ModuleMember -Function * `
                    -Alias ulItem `
                    -Variable sessions,
                              scriptParameters