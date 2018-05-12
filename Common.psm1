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
  while ($true) {
    $hadError = $false

    try {
      Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
      $global:Error.RemoveAt(0)

      Start-Sleep -Seconds 10
      $hadError = $true
    }

    if (-not $hadError) {
      break
    }
  }

  while ($true) {
    $hadError = $false

    try {
      Get-ADUser -Filter 'Name -eq "Administrator"' -ErrorAction Stop | Out-Null
    }
    catch {
      $global:Error.RemoveAt(0)

      Start-Sleep -Seconds 10
      $hadError = $true
    }

    if (-not $hadError) {
      break
    }
  }
}

function Join-Domain ([string]$Domain, [string]$User, [string]$Password) {
  $ping = New-Object System.Net.NetworkInformation.Ping

  while ($true) {
    try {
      $result = $ping.Send($Domain)
    }
    catch {

      # Catching an exception does not prevent the corresponding error from
      # being logged, although it does keep it from appearing in a visible
      # console window. Therefore, this method is required to prevent log
      # file output.
      $global:Error.RemoveAt(0)

      Start-Sleep -Seconds 5
    }

    if ($result -ne $null) {
      break
    }
  }

  $cred = New-Object System.Management.Automation.PSCredential @(
    $User,
    (ConvertTo-SecureString -String $Password -AsPlainText -Force)
  )

  # As of S2016TP5, a successful ping to the domain name does not in itself
  # signify readiness of a new domain controller (for a new forest) to take
  # domain join requests. Hence, I am forced to wrap Add-Computer itself in
  # a try-catch wrapper.
  while ($true) {
    try {
      $result = Add-Computer -DomainName  $Domain `
                             -Credential  $cred `
                             -ErrorAction Stop `
                             -PassThru
    }
    catch {
      $global:Error.RemoveAt(0)

      Start-Sleep -Seconds 5
    }

    if ($result.HasSucceeded -eq $true) {
      break
    }
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
    $DomainName,
    
    [string]
    $UserName,
    
    [string]
    $Password,

    [Parameter(
      ParameterSetName = "Count"
    )]
    [byte]
    $Count = 1,

    [Parameter(
      ParameterSetName = "Persist"
    )]
    [switch]
    $Persist
  )
  $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

  Set-ItemProperty -LiteralPath $path -Name AutoAdminLogon    -Value "1"         -Force
  Set-ItemProperty -LiteralPath $path -Name DefaultDomainName -Value $DomainName -Force
  Set-ItemProperty -LiteralPath $path -Name DefaultUserName   -Value $UserName   -Force
  Set-ItemProperty -LiteralPath $path -Name DefaultPassword   -Value $Password   -Force

  if ($PSCmdlet.ParameterSetName -eq "Count") {
    Set-ItemProperty -LiteralPath $path -Name AutoLogonCount -Value $Count -Type DWord -Force
  }
  elseif ($PSCmdlet.ParameterSetName -eq "Persist" -and (Get-Item -LiteralPath $path).Property -contains "AutoLogonCount") {
    Remove-ItemProperty -LiteralPath $path -Name AutoLogonCount -Force
  }
}

# PROVISO: If an active user account with a blank password has been set to
# autologon, clearing it in this manner will not actually stop the account
# from logging on at every reboot. The commonly suggested method for doing
# this online is to toggle the value "Enabled" at the following registry
# path:
#
# HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserSwitch
#
# However, this setting reverts with every restart unless additional measures
# are taken, and since the impacts of this change are unclear (some comments
# claim that it impacts Windows UAC), and the benefits so minor, I've decided
# not to implement it in any form.
function Clear-AutoLogon {
  $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

  Set-ItemProperty -LiteralPath $path -Name AutoAdminLogon -Value "0" -Force

  $propertiesAtPath = Get-Item -LiteralPath $path |
                        ForEach-Object Property

  "DefaultDomainName",
  "DefaultPassword",
  "AutoLogonCount",
  "AutoLogonSID" |
    ForEach-Object {
      if ($propertiesAtPath -contains $_) {
        Remove-ItemProperty -LiteralPath $path -Name $_ -Force
      }
    }
}

function Set-VolumeDriveLetter ([string]$FileSystemLabel, [string]$DriveLetter) {
  $volume = @(
    Get-Volume |
      Where-Object FileSystemLabel -eq $FileSystemLabel
  )

  if ($volume.Count -eq 0) {
    $offlineDisks = @(
      Get-Disk |
        Where-Object OperationalStatus -eq Offline |
        Where-Object PartitionStyle -ne RAW
    )

    if ($offlineDisks.Count -eq 0) {
      Write-Error "Could not assign drive letter. Volume with FileSystemLabel `"$FileSystemLabel`" was not found, and no offline disks on which it might reside were available."
      return
    }

    if ($offlineDisks.Count -ne 1) {
      Write-Error "Could not assign drive letter. Volume with FileSystemLabel `"$FileSystemLabel`" was not found, and there were multiple partitioned offline disks on which it might reside."
      return
    }

    $offlineDisks |
      Set-Disk -IsOffline $false

    $offlineDisks |
      Set-Disk -IsReadOnly $false

    $loopNumber = 1

    while ($loopNumber -le 2) {
      try {
        $volume = @(
          Get-Volume |
            Where-Object FileSystemLabel -eq $FileSystemLabel
        )

        if ($volume.Count -eq 0) {
          throw
        }
      }
      catch {
        Start-Sleep -Seconds 5
        $loopNumber++
        continue
      }

      break
    }
  }

  if ($volume.Count -eq 0) {
    Write-Error "Could not assign drive letter. Volume with FileSystemLabel `"$FileSystemLabel`" was not found."
    return
  }

  if ($volume.Count -gt 1) {
    Write-Error "Could not assign drive letter. Multiple volumes with FileSystemLabel `"$FileSystemLabel`" were found."
    return
  }

  $partition = $volume |
                 Get-Partition

  if ($partition.DriveLetter -ne $DriveLetter) {
    $partition |
      Set-Partition -NewDriveLetter $DriveLetter
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

function Wait-CTBackInfo ($ProfileName) {
  $tempPath = "C:\Users\$ProfileName\AppData\Local\Temp"

  $logPath = "C:\Users\$ProfileName\AppData\Local\Temp\CTBackInfo.log"

  $startTime = Get-Date

  $lastBootTime = Get-WmiObject Win32_OperatingSystem |
                    ForEach-Object {$_.ConvertToDateTime($_.LastBootUpTime)}

  $logDetected = $false

  do {
    Start-Sleep -Seconds 60

    $logPaths = (@(
      $tempPath
    ) + @(
      Get-ChildItem -LiteralPath $tempPath |
        Where-Object {$_ -is [System.IO.DirectoryInfo]} |
        Where-Object {$_.Name -match "^[1-9]\d*$"} |
        ForEach-Object FullName
    )) |
      ForEach-Object {
        Join-Path -Path $_ -ChildPath CTBackInfo.log
      }

    $logDetected = @(
      $logPaths |
        Where-Object {
          (Test-Path -LiteralPath $_) -and (Get-Item -LiteralPath $_).LastWriteTime -gt $lastBootTime
        }
    ).Count -gt 0
  } while ((-not $logDetected) -and (((Get-Date) - $startTime).TotalMinutes -lt 5))

  if (-not ($logDetected)) {
    Write-Error "Updated CTBackInfo log path for profile `"$ProfileName`" not detected within 5 minutes."
  }
}
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

$scriptParameters = $null
if (Test-Path -LiteralPath $PSScriptRoot\ScriptParameters.json) {
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

  $global:Error | Out-File -LiteralPath $script:errorLogPath -Append -Width ([int]::MaxValue)

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

Export-ModuleMember -Function * -Variable sessions,
                                          scriptParameters