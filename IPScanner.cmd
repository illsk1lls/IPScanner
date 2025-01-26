<# :: Hybrid CMD / Powershell Launcher - Rename file to .CMD to Autolaunch with console settings (Double-Click) - Rename to .PS1 to run as Powershell script without console settings
@ECHO OFF
SET "0=%~f0"&SET "LEGACY={B23D10C0-E52E-411E-9D5B-C09FDF709C7D}"&SET "LETWIN={00000000-0000-0000-0000-000000000000}"&SET "TERMINAL={2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}"&SET "TERMINAL2={E12CFF52-A866-4C77-9A90-F570A7AA2C6B}"
POWERSHELL -nop -c "Get-WmiObject -Class Win32_OperatingSystem | Select -ExpandProperty Caption | Find 'Windows 11'">nul
IF ERRORLEVEL 0 (
	SET isEleven=1
	>nul 2>&1 REG QUERY "HKCU\Console\%%%%Startup" /v DelegationConsole
	IF ERRORLEVEL 1 (
		REG ADD "HKCU\Console\%%%%Startup" /v DelegationConsole /t REG_SZ /d "%LETWIN%" /f>nul
		REG ADD "HKCU\Console\%%%%Startup" /v DelegationTerminal /t REG_SZ /d "%LETWIN%" /f>nul
	)
	FOR /F "usebackq tokens=3" %%# IN (`REG QUERY "HKCU\Console\%%%%Startup" /v DelegationConsole 2^>nul`) DO (
		IF NOT "%%#"=="%LEGACY%" (
			SET "DEFAULTCONSOLE=%%#"
			REG ADD "HKCU\Console\%%%%Startup" /v DelegationConsole /t REG_SZ /d "%LEGACY%" /f>nul
			REG ADD "HKCU\Console\%%%%Startup" /v DelegationTerminal /t REG_SZ /d "%LEGACY%" /f>nul
		)
	)
)
START /MIN "" POWERSHELL -nop -c "iex ([io.file]::ReadAllText('%~f0'))">nul
IF "%isEleven%"=="1" (
	IF DEFINED DEFAULTCONSOLE (
		IF "%DEFAULTCONSOLE%"=="%TERMINAL%" (
			REG ADD "HKCU\Console\%%%%Startup" /v DelegationConsole /t REG_SZ /d "%TERMINAL%" /f>nul
			REG ADD "HKCU\Console\%%%%Startup" /v DelegationTerminal /t REG_SZ /d "%TERMINAL2%" /f>nul
		) ELSE (
			REG ADD "HKCU\Console\%%%%Startup" /v DelegationConsole /t REG_SZ /d "%DEFAULTCONSOLE%" /f>nul
			REG ADD "HKCU\Console\%%%%Startup" /v DelegationTerminal /t REG_SZ /d "%DEFAULTCONSOLE%" /f>nul
		)
	)
)
EXIT
#>if($env:0){$PSCommandPath="$env:0"}
###POWERSHELL BELOW THIS LINE###

# Hide Console - Show GUI Only - Only works for Legacy console
Add-Type -MemberDefinition '[DllImport("User32.dll")]public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -Namespace Win32 -Name Functions
$closeConsoleUseGUI=[Win32.Functions]::ShowWindow((Get-Process -Id $PID).MainWindowHandle,0)

# Allow Single Instance Only
$AppId = 'Simple IP Scanner'
$singleInstance = $false
$script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true,([Threading.EventResetMode]::ManualReset),"Global\$AppId",([ref] $singleInstance)
if (-not $singleInstance){
	$shell = New-Object -ComObject Wscript.Shell
	$shell.Popup("$AppId is already running!",0,'ERROR:',0x0) | Out-Null
	Exit
}

# GUI Main Dispatcher
function Update-uiMain(){
	$Main.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Background, [action]{})
}

function Update-Progress {
	param ($value, $text)
	$Progress.Value = $value
	$BarText.Text = $text
	Update-uiMain
}

# Find gateway
$route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1
$global:gateway = $route.NextHop
$gatewayParts = $global:gateway -split '\.'
$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

# Store the original gateway prefix for reset functionality
$originalGatewayPrefix = $global:gatewayPrefix

# Initialize RunspacePool
$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount, $SessionState, $Host)
$RunspacePool.Open()

# Get Host Info
function Get-HostInfo {
	param(
		[string]$gateway,
		[string]$gatewayPrefix,
		[string]$originalGatewayPrefix
	)
	$getHostInfoScriptBlock = {
		param(
			[string]$gateway,
			[string]$gatewayPrefix,
			[string]$originalGatewayPrefix
		)
		# Get Hostname
		$hostName = [System.Net.Dns]::GetHostName()

		# Check internet connection and get external IP
		$ProgressPreference = 'SilentlyContinue'
		try {
			$ncsiCheck = Invoke-RestMethod "http://www.msftncsi.com/ncsi.txt"
			if ($ncsiCheck -eq "Microsoft NCSI") {
				$externalIP = Invoke-RestMethod "http://ifconfig.me/ip"
			} else {
				$externalIP = "No Internet or Redirection"
			}
		} catch {
			$externalIP = "No Internet or Error"
		}
		$ProgressPreference = 'Continue'

		# Use the passed gateway and gatewayPrefix
		$internalIP = (Get-NetIPAddress | Where-Object {
			$_.AddressFamily -eq 'IPv4' -and
			$_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and
			$_.IPAddress -like "$originalGatewayPrefix*"
		}).IPAddress

		# Get current adapter
		$adapter = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
			$_.InterfaceAlias -match 'Ethernet|Wi-Fi' -and
			$_.IPAddress -like "$originalGatewayPrefix*"
		}).InterfaceAlias

		# Get MAC address
		$myMac = (Get-NetAdapter -Name $adapter).MacAddress -replace '-', ':'

		# Get domain
		$domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain

		# Init ARP cache data
		$arpInit = Get-NetNeighbor | Where-Object {($_.State -eq "Reachable" -or $_.State -eq "Stale") -and ($_.IPAddress -like "$gatewayPrefix*") -and -not $_.IPAddress.Contains(':')} | Select-Object -Property IPAddress, LinkLayerAddress

		# Mark empty as unknown
		$variables = @('hostName', 'externalIP', 'internalIP', 'gateway', 'domain')
		foreach ($item in $variables) {
			if (-not (Get-Variable -Name $item -ValueOnly)) {
				Set-Variable -Name $item -Value 'Unknown'
			}
		}

		return @{
			'hostName' = $hostName;
			'externalIP' = $externalIP;
			'internalIP' = $internalIP;
			'gateway' = $gateway;
			'gatewayPrefix' = $gatewayPrefix;
			'adapter' = $adapter;
			'myMac' = $myMac;
			'domain' = $domain;
			'arpInit' = $arpInit;
		}
	}

	$getHostInfoThread = [powershell]::Create().AddScript($getHostInfoScriptBlock)
	$getHostInfoThread.AddArgument($global:gateway)
	$getHostInfoThread.AddArgument($global:gatewayPrefix)
	$getHostInfoThread.AddArgument($originalGatewayPrefix)
	$getHostInfoThread.RunspacePool = $RunspacePool
	$getHostInfoAsync = $getHostInfoThread.BeginInvoke()
	$getHostInfoAsync.AsyncWaitHandle.WaitOne()
	$hostInfoResults = $getHostInfoThread.EndInvoke($getHostInfoAsync)
	$global:hostName = $hostInfoResults.hostName
	$global:externalIP = $hostInfoResults.externalIP
	$global:internalIP = $hostInfoResults.internalIP
	$global:gateway = $hostInfoResults.gateway
	$global:gatewayPrefix = $hostInfoResults.gatewayPrefix
	$global:adapter = $hostInfoResults.adapter
	$global:myMac = $hostInfoResults.myMac
	$global:domain = $hostInfoResults.domain
	$global:arpInit = $hostInfoResults.arpInit
	Update-Progress 0 'Scanning'
	$getHostInfoThread.Dispose()
}

# Send packets across subnet
function Scan-Subnet {
	$scanSubnetScriptBlock = {
		param (
			[string]$gatewayPrefix
		)

		$pingAll = 1..254 | ForEach-Object {
			"$gatewayPrefix$_"
		}
		Test-Connection -ComputerName $pingAll -Count 1 -AsJob | Out-Null
		Get-Job | Wait-Job -ErrorAction Stop | Out-Null
		$results = Get-Job | Receive-Job -ErrorAction Stop
		$successfulPings = @($results | Where-Object { $_.StatusCode -eq 0 } | Select-Object -ExpandProperty Address)
		Get-Job | Remove-Job -Force

		return $successfulPings
	}
	$scanSubnetThread = [powershell]::Create().AddScript($scanSubnetScriptBlock)
	$scanSubnetThread.RunspacePool = $RunspacePool
	$scanSubnetThread.AddArgument($global:gatewayPrefix)
	$scanSubnetAsync = $scanSubnetThread.BeginInvoke()
	$scanSubnetAsync.AsyncWaitHandle.WaitOne()
	$global:successfulPings = $scanSubnetThread.EndInvoke($scanSubnetAsync)
	$scanSubnetThread.Dispose()
}

# Create peer list
function List-Machines {
	Update-Progress 0 'Identifying Devices'

	# Convert IP Addresses from string to int by each section
	$arpOutput = $arpInit | Sort-Object -Property {$ip = $_.IPaddress; $ip -split '\.' | ForEach-Object {[int]$_}}

	$self = 0
	$myLastOctet = [int]($internalIP -split '\.')[-1]

	# Get Vendor via Mac (thanks to u/mprz)
	$ProgressPreference = 'SilentlyContinue'
	$tryMyVendor = (irm "https://www.macvendorlookup.com/api/v2/$($myMac.Replace(':','').Substring(0,6))" -Method Get).Company
	$ProgressPreference = 'Continue'
	$myVendor = if($tryMyVendor){$tryMyVendor.substring(0, [System.Math]::Min(35, $tryMyVendor.Length))} else {'Unable to Identify'}

	# Cycle through ARP table to populate initial ListView data and start async lookups
	$totalItems = ($arpOutput.Count - 1)

	# First, add all known ARP entries
	foreach ($line in $arpOutput) {
		$ip = $line.IPAddress
		$mac = $line.LinkLayerAddress.Replace('-',':')
		$name = if ($ip -eq $internalIP) {"$hostName (This Device)"} else {"Resolving..."}
		$vendor = if ($ip -eq $internalIP) {$myVendor} else {"Identifying..."}

		# Determine if the IP was pingable
		$pingResult = $ip -in $global:successfulPings
		$pingImage = Create-GradientEllipse -isPingSuccessful $pingResult

		# Format and display
		$lastOctet = [int]($ip -split '\.')[-1]
		if ($myLastOctet -gt $lastOctet) {
			$item = [pscustomobject]@{
				'MACaddress' = $mac;
				'Vendor' = $vendor;
				'IPaddress' = $ip;
				'HostName' = $name;
				'Ping' = $pingResult
				'PingImage' = $pingImage
			}
			$listView.Items.Add($item)
		} else {
			if ($self -ge 1) {
				$item = [pscustomobject]@{
					'MACaddress' = $mac;
					'Vendor' = $vendor;
					'IPaddress' = $ip;
					'HostName' = $name;
					'Ping' = $pingResult
					'PingImage' = $pingImage
				}
				$listView.Items.Add($item)
			} else {
				$myPingTrueIcon = Create-GradientEllipse -isPingSuccessful $true
				$listView.Items.Add([pscustomobject]@{
					'MACaddress' = $myMac;
					'Vendor' = $myVendor;
					'IPaddress' = $internalIP;
					'HostName' = "$hostName (This Device)";
					'Ping' = $true
					'PingImage' = $myPingTrueIcon
				})
				$item = [pscustomobject]@{
					'MACaddress' = $mac;
					'Vendor' = $vendor;
					'IPaddress' = $ip;
					'HostName' = $name;
					'Ping' = $pingResult
					'PingImage' = $pingImage
				}
				$listView.Items.Add($item)
				$self++
			}
		}
	}

	# Now add entries for successful pings not in ARP data, excluding the internal IP
	$successfulPingsNotInARP = $global:successfulPings | Where-Object { $_ -notin $arpOutput.IPAddress -and $_ -ne $internalIP }
	foreach ($ip in $successfulPingsNotInARP) {
		$item = [pscustomobject]@{
			'MACaddress' = 'No ARP Data';
			'Vendor' = 'Unknown';
			'IPaddress' = $ip;
			'HostName' = 'Resolving...';
			'Ping' = $true;
			'PingImage' = Create-GradientEllipse -isPingSuccessful $true
		}
		$listView.Items.Add($item)
	}

	# Sort ListView items by IP address in ascending order
	$sortedItems = $listView.Items | Sort-Object -Property {[version]$_.IPaddress}
	$listView.Items.Clear()
	$sortedItems | ForEach-Object { $listView.Items.Add($_) }
	$listView.Items.Refresh()

	if ($totalItems -ge 19) {
		$hostNameColumn.Width = 270
	}
	Update-uiMain
}

# Background Vendor lookup
function processVendors {
	$vendorLookupThread = [powershell]::Create().AddScript({
		param ($Main, $listView, $internalIP)

		function Update-uiBackground{
			param($action)
			$Main.Dispatcher.Invoke([action]$action, [Windows.Threading.DispatcherPriority]::Background)
		}

		$vendorTasks = @{}

		# Process found devices
		foreach ($item in $listView.Items) {
			$ip = $item.IPaddress
			$mac = $item.MACaddress
			if ($ip -ne $internalIP) {
				$vendorTask = Start-Job -ScriptBlock {
					param($mac)
					$ProgressPreference = 'SilentlyContinue'
					$response = (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get)
					$ProgressPreference = 'SilentlyContinue'
					if([string]::IsNullOrEmpty($response.Company)){
						return $null
					} else {
						return $response
					}
				} -ArgumentList $mac
				$vendorTasks[$ip] = $vendorTask
				do {
					# Process vendor tasks
					foreach ($ipCheck in @($vendorTasks.Keys)) {
						if ($vendorTasks[$ipCheck].State -eq "Completed") {
							$result = Receive-Job -Job $vendorTasks[$ipCheck]
							$vendorResult = if ($result -and $result.Company) {
								$result.Company.substring(0, [System.Math]::Min(35, $result.Company.Length))
							} else {
								'Unable to Identify'
							}
							foreach ($it in $listView.Items) {
								if ($it.IPaddress -eq $ipCheck) {
									Update-uiBackground{
										$it.Vendor = $vendorResult
										$listView.Items.Refresh()
									}
								}
							}
							$vendorTasks.Remove($ipCheck)
						}
					}
					Start-Sleep -Milliseconds 50
				} while ($vendorTasks.Count -ge 5)
			}
		}

		# Temp bugfix for unidentified runaway, last listitem background job always closes before returning a value
		$lastItem = $listView.Items | Select-Object -Last 1
		$lastIP = $lastItem.IPaddress
		$lastMAC = $lastItem.MACaddress
		# Check Vendor
		if ($lastItem.Vendor -eq 'Identifying...' -or $lastItem.Vendor -eq 'Unable to Identify') {
			# Manual vendor lookup for the last IP only if needed
			$ProgressPreference = 'SilentlyContinue'
			$lastVendor = (irm "https://www.macvendorlookup.com/api/v2/$($lastMAC.Replace(':','').Substring(0,6))" -Method Get)
			$ProgressPreference = 'Continue'
			$lastVendorResult = if ($lastVendor -and $lastVendor.Company) {
				$lastVendor.Company.substring(0, [System.Math]::Min(35, $lastVendor.Company.Length))
			} else {
				'Unable to Identify'
			}
			Update-uiBackground{
				$lastItem.Vendor = $lastVendorResult
				$listView.Items.Refresh()
			}
		}

		# Update any leftover orphans
		foreach ($item in $listView.Items) {
			if ($item.Vendor -eq 'Identifying...') {
				Update-uiBackground{
					$item.Vendor = 'Unable to Identify'
					$listView.Items.Refresh()
				}
			}
		}

		# Clean up jobs
		Remove-Job -Job $vendorTasks.Values -Force

	}, $true).AddArgument($Main).AddArgument($listView).AddArgument($internalIP)
	$vendorLookupThread.RunspacePool = $RunspacePool
	$vendorScan = $vendorLookupThread.BeginInvoke()
}

# Process Hostnames
function processHostnames {
	$hostnameLookupThread = [powershell]::Create().AddScript({
		param ($Main, $listView, $internalIP)

		function Update-uiBackground{
			param($action)
			$Main.Dispatcher.Invoke([action]$action, [Windows.Threading.DispatcherPriority]::Background)
		}

		$hostnameTasks = @{}

		# Process found devices
		foreach ($item in $listView.Items) {
			$ip = $item.IPaddress
			$mac = $item.MACaddress
			if ($ip -ne $internalIP) {
				$hostTask = [System.Net.Dns]::GetHostEntryAsync($ip)
				$hostnameTasks[$ip] = [PSCustomObject]@{Task = $hostTask; IP = $ip}
				do {
					# Process hostname tasks
					foreach ($ipCheck in @($hostnameTasks.Keys)) {
						if ($hostnameTasks[$ipCheck].Task.IsCompleted) {
							$entry = $hostnameTasks[$ipCheck].Task.Result
							foreach ($it in $listView.Items) {
								if ($it.IPaddress -eq $ipCheck) {
									if ([string]::IsNullOrEmpty($entry.HostName)) {
										Update-uiBackground {
											$it.HostName = "Unable to Resolve"
											$listView.Items.Refresh()
										}
									} else {
										Update-uiBackground {
											$it.HostName = $entry.HostName
											$listView.Items.Refresh()
										}
									}
								}
							}
							$hostnameTasks.Remove($ipCheck)
						}
					}
					Start-Sleep -Milliseconds 50
				} while ($hostnameTasks.Count -ge 5)
			}
		}

		# Temp bugfix for unidentified runaway, last listitem background job always closes before returning a value
		$lastItem = $listView.Items | Select-Object -Last 1
		$lastIP = $lastItem.IPaddress
		$lastMAC = $lastItem.MACaddress
		# Check HostName
		if ($lastItem.HostName -eq 'Resolving...' -or $lastItem.HostName -eq 'Unable to Resolve') {
			# Manual hostname lookup for the last IP only if needed
			try {
				$dnsEntry = [System.Net.Dns]::GetHostEntryAsync($lastIP).Result
				$lastHostName = if ($dnsEntry.HostName) { $dnsEntry.HostName } else { 'Unable to Resolve' }
			} catch {
				$lastHostName = 'Unable to Resolve'
			}
			Update-uiBackground{
				$lastItem.HostName = $lastHostName
				$listView.Items.Refresh()
			}
		}

		# Update any leftover orphans
		foreach ($item in $listView.Items) {
			if ($item.HostName -eq 'Resolving...') {
				Update-uiBackground{
					$item.HostName = 'Unable to Resolve'
					$listView.Items.Refresh()
				}
			}
		}

		# Clean up jobs
		Remove-Job -Job $hostnameTasks.Values -Force

	}, $true).AddArgument($Main).AddArgument($listView).AddArgument($internalIP)
	$hostnameLookupThread.RunspacePool = $RunspacePool
	$hostnameScan = $hostnameLookupThread.BeginInvoke()
}

# Portscan
function CheckConnectivity {
	param (
		[string]$selectedhost
	)
	# Disable all buttons for 'This Device'
	if ($selectedhost -match ' (This Device)') {
		@('btnRDP', 'btnWebInterface', 'btnShare', 'btnNone') | ForEach-Object {
			Get-Variable $_ -ValueOnly | ForEach-Object {
				$_.IsEnabled = $false
				$_.Visibility = 'Collapsed'
			}
		}
		$btnNone.IsEnabled = $true
		$btnNone.Visibility = 'Visible'
		return
	}
	$global:tryToConnect = $selectedhost -replace ' (This Device)', ''

	# Find the item in ListView based on IP or HostName
	$selectedItem = $listView.Items | Where-Object {
		$_.IPaddress -eq $tryToConnect -or $_.HostName -eq $selectedhost
	} | Select-Object -First 1

	# Check connectivity for different protocols
	$ports = @{
		HTTP = 80
		HTTPS = 443
		SMBv2 = 445
		SMB = 139
		RDP = 3389
	}
	$results = @{}
	foreach ($protocol in $ports.Keys) {
		$client = [System.Net.Sockets.TcpClient]::new()
		$results[$protocol] = $client.ConnectAsync($tryToConnect, $ports[$protocol]).Wait(250)
		$client.Close()
	}

	# Update button states based on connectivity results
	$btnShare.IsEnabled = ($results.SMBv2 -or $results.SMB) -and $HostName -ne $tryToConnect
	$btnShare.Visibility = if ($btnShare.IsEnabled) { 'Visible' } else { 'Collapsed' }

	if ($btnShare.Visibility -eq 'Visible') {$btnWebInterface.Margin = "0,0,25,0"} else {$btnWebInterface.Margin = "0,0,0,0"}
	$btnWebInterface.IsEnabled = ($results.HTTP -or $results.HTTPS) -and $HostName -ne $tryToConnect
	$btnWebInterface.Visibility = if ($btnWebInterface.IsEnabled) { 'Visible' } else { 'Collapsed' }
	$global:httpAvailable = if ($results.HTTP) { 1 } else { 0 }

	if ($btnShare.Visibility -eq 'Visible' -or $btnWebInterface.Visibility -eq 'Visible') {$btnRDP.Margin = "0,0,25,0"} else {$btnRDP.Margin = "0,0,0,0"}
	$btnRDP.IsEnabled = $results.RDP -and $HostName -ne $tryToConnect
	$btnRDP.Visibility = if ($btnRDP.IsEnabled) { 'Visible' } else { 'Collapsed' }

	# Show no connections icon if nothing is available
	if (-not $btnRDP.IsEnabled -and -not $btnWebInterface.IsEnabled -and -not $btnShare.IsEnabled) {
		$btnNone.IsEnabled = $true
		$btnNone.Visibility = 'Visible'
	} else {
		$btnNone.IsEnabled = $false
		$btnNone.Visibility = 'Collapsed'
	}

	# Show ping response status in popup window
	$pingStatusImage.Content = if ($selectedItem.Ping) { Create-GradientEllipse -isPingSuccessful $true -width 12 -height 12 } else { Create-GradientEllipse -isPingSuccessful $false -width 12 -height 12	}
	$pingStatusText.Text = if ($selectedItem.Ping) { "ICMP response received" } else { "No ICMP response received" }
}

# Listview column sort logic
$sortDirections = @{}
$listViewSortColumn = {
	param([System.Object]$sender, [System.EventArgs]$Event)
	$SortPropertyName = $Event.OriginalSource.Column.DisplayMemberBinding.Path.Path

	# Determine current direction, toggle if column has been sorted before
	switch ($true) {
		{$sortDirections.ContainsKey($SortPropertyName)} {
			$sortDirections[$SortPropertyName] = -not $sortDirections[$SortPropertyName]
		}
		default {
			# false for descending, true for ascending
			$sortDirections[$SortPropertyName] = $false
		}
	}
	$direction = if ($sortDirections[$SortPropertyName]) { "Ascending" } else { "Descending" }

	# Sort items
	switch ($SortPropertyName) {
		"IPaddress" {
			$sortedItems = $Sender.Items | Sort-Object -Property @{Expression={[version]$_.IPaddress}; $direction=$true}
		}
		default {
			$sortedItems = $Sender.Items | Sort-Object -Property $SortPropertyName -Descending:($direction -eq "Descending")
		}
	}

	# Update ListView
	$Sender.Items.Clear()
	$sortedItems | ForEach-Object { $Sender.Items.Add($_) }
}

function Create-GradientEllipse {
	param (
		[bool]$isPingSuccessful,
		[double]$width = 9,
		[double]$height = 9
	)

	$ellipse = [Windows.Shapes.Ellipse]::new()
	$ellipse.Width = $width
	$ellipse.Height = $height

	if ($isPingSuccessful) {
		# Lighter blue gradient for successful ping
		$gradient = New-Object System.Windows.Media.RadialGradientBrush
		$gradient.GradientOrigin = New-Object System.Windows.Point(0.5, 0.5)
		$gradient.Center = New-Object System.Windows.Point(0.5, 0.5)
		$gradient.RadiusX = 0.5
		$gradient.RadiusY = 0.5
		$stop1 = New-Object System.Windows.Media.GradientStop
		$stop1.Color = [System.Windows.Media.Color]::FromArgb(255, 51, 204, 255)
		$stop1.Offset = 0
		$gradient.GradientStops.Add($stop1)
		$stop2 = New-Object System.Windows.Media.GradientStop
		$stop2.Color = [System.Windows.Media.Color]::FromArgb(255, 25, 153, 204)
		$stop2.Offset = 0.8
		$gradient.GradientStops.Add($stop2)
		$stop3 = New-Object System.Windows.Media.GradientStop
		$stop3.Color = [System.Windows.Media.Color]::FromArgb(255, 0, 102, 153)
		$stop3.Offset = 1
		$gradient.GradientStops.Add($stop3)
	} else {
		# Shades of gray for unsuccessful ping
		$gradient = New-Object System.Windows.Media.RadialGradientBrush
		$gradient.GradientOrigin = New-Object System.Windows.Point(0.5, 0.5)
		$gradient.Center = New-Object System.Windows.Point(0.5, 0.5)
		$gradient.RadiusX = 0.5
		$gradient.RadiusY = 0.5
		$stop4 = New-Object System.Windows.Media.GradientStop
		$stop4.Color = [System.Windows.Media.Color]::FromArgb(255, 220, 220, 220)
		$stop4.Offset = 0
		$gradient.GradientStops.Add($stop4)
		$stop5 = New-Object System.Windows.Media.GradientStop
		$stop5.Color = [System.Windows.Media.Color]::FromArgb(255, 160, 160, 160)
		$stop5.Offset = 0.8
		$gradient.GradientStops.Add($stop5)
		$stop6 = New-Object System.Windows.Media.GradientStop
		$stop6.Color = [System.Windows.Media.Color]::FromArgb(255, 100, 100, 100)
		$stop6.Offset = 1
		$gradient.GradientStops.Add($stop6)
	}

	$ellipse.Fill = $gradient
	return $ellipse
}

# get icons from DLL or EXE files via shell32.dll function calls
$getIcons = @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows;

namespace System
{
	public class IconExtractor
	{
		public static Icon Extract(string file, int number, bool largeIcon)
		{
			IntPtr large;
			IntPtr small;
			ExtractIconEx(file, number, out large, out small, 1);
			try
			{
				return Icon.FromHandle(largeIcon ? large : small);
			}
			catch
			{
				return null;
			}
		}
		public static BitmapSource IconToBitmapSource(Icon icon)
		{
			return Imaging.CreateBitmapSourceFromHIcon(
				icon.Handle,
				Int32Rect.Empty,
				BitmapSizeOptions.FromEmptyOptions());
		}
		[DllImport("Shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
		private static extern int ExtractIconEx(string sFile, int iIndex, out IntPtr piLargeVersion, out IntPtr piSmallVersion, int amountIcons);
	}
}
"@

# Define WPF GUI Structure
Add-Type -TypeDefinition $getIcons -ReferencedAssemblies System.Windows.Forms, System.Drawing, PresentationCore, PresentationFramework, WindowsBase
[xml]$XAML = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Height="500" Width="900" Background="Transparent" AllowsTransparency="True" WindowStyle="None">
	<Window.Resources>
		<ControlTemplate x:Key="NoMouseOverButtonTemplate" TargetType="Button">
			<Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
				<ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
			</Border>
			<ControlTemplate.Triggers>
				<Trigger Property="IsEnabled" Value="False">
					<Setter Property="Background" Value="{x:Static SystemColors.ControlLightBrush}"/>
					<Setter Property="Foreground" Value="{x:Static SystemColors.GrayTextBrush}"/>
				</Trigger>
			</ControlTemplate.Triggers>
		</ControlTemplate>
		<ControlTemplate x:Key="CloseButtonTemplate" TargetType="Button">
			<Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="0,5,0,0">
				<ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
			</Border>
			<ControlTemplate.Triggers>
				<Trigger Property="IsEnabled" Value="False">
					<Setter Property="Background" Value="{x:Static SystemColors.ControlLightBrush}"/>
					<Setter Property="Foreground" Value="{x:Static SystemColors.GrayTextBrush}"/>
				</Trigger>
			</ControlTemplate.Triggers>
		</ControlTemplate>
		<ControlTemplate x:Key="NoMouseOverColumnHeaderTemplate" TargetType="{x:Type GridViewColumnHeader}">
			<Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
				<ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}" RecognizesAccessKey="True"/>
			</Border>
			<ControlTemplate.Triggers>
				<Trigger Property="IsEnabled" Value="False">
					<Setter Property="Background" Value="{x:Static SystemColors.ControlLightBrush}"/>
					<Setter Property="Foreground" Value="{x:Static SystemColors.GrayTextBrush}"/>
				</Trigger>
			</ControlTemplate.Triggers>
		</ControlTemplate>
		<Style x:Key="ScrollThumbs" TargetType="{x:Type Thumb}">
			<Setter Property="Template">
				<Setter.Value>
					<ControlTemplate TargetType="{x:Type Thumb}">
						<Grid x:Name="Grid">
							<Rectangle HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Width="Auto" Height="Auto" Fill="Transparent"/>
							<Border x:Name="Rectangle1" CornerRadius="5" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Width="Auto" Height="Auto" Background="{TemplateBinding Background}"/>
						</Grid>
						<ControlTemplate.Triggers>
							<Trigger Property="Tag" Value="Horizontal">
								<Setter TargetName="Rectangle1" Property="Width" Value="Auto"/>
								<Setter TargetName="Rectangle1" Property="Height" Value="7"/>
							</Trigger>
						</ControlTemplate.Triggers>
					</ControlTemplate>
				</Setter.Value>
			</Setter>
		</Style>
		<Style x:Key="{x:Type ScrollBar}" TargetType="{x:Type ScrollBar}">
			<Setter Property="Stylus.IsPressAndHoldEnabled" Value="True"/>
			<Setter Property="Stylus.IsFlicksEnabled" Value="True" />
			<Setter Property="Background" Value="#333333"/>
			<Setter Property="BorderThickness" Value="1,0"/>
			<Setter Property="BorderBrush" Value="#000000"/>
			<Setter Property="Template">
				<Setter.Value>
					<ControlTemplate TargetType="{x:Type ScrollBar}">
						<Grid x:Name="GridRoot" Width="{TemplateBinding Width}" Height="{TemplateBinding Height}" SnapsToDevicePixels="True">
							<Track x:Name="PART_Track" IsDirectionReversed="true" Focusable="false">
								<Track.Thumb>
									<Thumb x:Name="Thumb" Style="{StaticResource ScrollThumbs}" Background="#777777" />
								</Track.Thumb>
							</Track>
						</Grid>
					</ControlTemplate>
				</Setter.Value>
			</Setter>
			<Style.Triggers>
				<Trigger Property="Orientation" Value="Vertical">
					<Setter Property="Width" Value="10" />
					<Setter Property="Height" Value="396" />
					<Setter Property="MinHeight" Value="396" />
					<Setter Property="MinWidth" Value="10" />
				</Trigger>
				<Trigger Property="Orientation" Value="Horizontal">
					<Setter Property="Width" Value="845" />
					<Setter Property="Height" Value="10" />
					<Setter Property="MinHeight" Value="10" />
					<Setter Property="MinWidth" Value="845" />
					<Setter Property="Margin" Value="-2,0,0,0" />
				</Trigger>
			</Style.Triggers>
		</Style>
		<Style x:Key="ColumnHeaderStyle" TargetType="{x:Type GridViewColumnHeader}">
			<Setter Property="Template" Value="{StaticResource NoMouseOverColumnHeaderTemplate}" />
			<Setter Property="Background" Value="#CCCCCC" />
			<Setter Property="Foreground" Value="Black" />
			<Setter Property="BorderBrush" Value="#333333" />
			<Setter Property="BorderThickness" Value="0,0,2,0" />
			<Setter Property="Cursor" Value="Arrow" />
			<Setter Property="FontWeight" Value="Bold"/>
			<Style.Triggers>
				<Trigger Property="IsMouseOver" Value="True">
					<Setter Property="Background" Value="#EEEEEE" />
					<Setter Property="Foreground" Value="Black" />
					<Setter Property="BorderBrush" Value="#333333" />
				</Trigger>
			</Style.Triggers>
		</Style>
		<Style x:Key="CustomContextMenuStyle" TargetType="{x:Type ContextMenu}">
			<Setter Property="Background" Value="#666666"/>
			<Setter Property="Foreground" Value="#EEEEEE"/>
			<Setter Property="BorderBrush" Value="#333333"/>
			<Setter Property="BorderThickness" Value="0,0,2,0"/>
			<Setter Property="OverridesDefaultStyle" Value="True"/>
			<Setter Property="Template">
				<Setter.Value>
					<ControlTemplate TargetType="{x:Type ContextMenu}">
						<Border CornerRadius="2,4,4,2" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
							<StackPanel>
								<ItemsPresenter/>
							</StackPanel>
						</Border>
					</ControlTemplate>
				</Setter.Value>
			</Setter>
		</Style>
		<Style x:Key="CustomMenuItemStyle" TargetType="{x:Type MenuItem}">
			<Setter Property="Background" Value="#666666"/>
			<Setter Property="Foreground" Value="#EEEEEE"/>
			<Setter Property="Template">
				<Setter.Value>
					<ControlTemplate TargetType="{x:Type MenuItem}">
						<Border x:Name="Border" BorderThickness="0.70" CornerRadius="2,4,4,4" Background="Transparent" SnapsToDevicePixels="True" Padding="12,3,12,3">
							<Grid>
								<Grid.ColumnDefinitions>
									<ColumnDefinition Width="Auto"/>
									<ColumnDefinition Width="Auto"/>
								</Grid.ColumnDefinitions>
								<ContentPresenter Margin="1" ContentSource="Header" RecognizesAccessKey="True" Grid.Column="0"/>
								<Popup x:Name="PART_Popup" Placement="Right" VerticalOffset="-5" HorizontalOffset="5" AllowsTransparency="True" IsOpen="{Binding IsSubmenuOpen, RelativeSource={RelativeSource TemplatedParent}}" PopupAnimation="Fade">
									<Border x:Name="SubMenuBorder" CornerRadius="2,4,4,4" SnapsToDevicePixels="True" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="0.70">
										<StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle"/>
									</Border>
								</Popup>
							</Grid>
						</Border>
						<ControlTemplate.Triggers>
							<Trigger Property="IsHighlighted" Value="true">
								<Setter Property="Background" TargetName="Border" Value="#4000B7FF"/>
								<Setter Property="BorderBrush" TargetName="Border" Value="#FF00BFFF"/>
							</Trigger>
							<Trigger Property="IsEnabled" Value="False">
								<Setter Property="Foreground" Value="#888888"/>
							</Trigger>
						</ControlTemplate.Triggers>
					</ControlTemplate>
				</Setter.Value>
			</Setter>
		</Style>
		<Style x:Key="MainMenuItemStyle" TargetType="{x:Type MenuItem}">
			<Setter Property="Background" Value="#666666"/>
			<Setter Property="Foreground" Value="#EEEEEE"/>
			<Setter Property="Template">
				<Setter.Value>
					<ControlTemplate TargetType="{x:Type MenuItem}">
						<Border x:Name="Border" BorderThickness="0.70" CornerRadius="2,4,4,4" Background="Transparent" SnapsToDevicePixels="True" Padding="12,3,12,3">
							<Grid>
								<Grid.ColumnDefinitions>
									<ColumnDefinition Width="Auto"/>
									<ColumnDefinition Width="Auto"/>
								</Grid.ColumnDefinitions>
								<ContentPresenter Margin="1" ContentSource="Header" RecognizesAccessKey="True" Grid.Column="0"/>
								<Path x:Name="BlackArrow" Data="M0 0 L5 2.5 L0 5 Z" Width="5" Height="5" Margin="7,2,0,0" Grid.Column="1">
									<Path.Fill>
										<SolidColorBrush Color="#EEEEEE"/>
									</Path.Fill>
								</Path>
								<Path x:Name="GrayArrow" Data="M0 0 L5 2.5 L0 5 Z" Width="5" Height="5" Margin="7,2,0,0" Grid.Column="1">
									<Path.Fill>
										<SolidColorBrush Color="#888888"/>
									</Path.Fill>
								</Path>
								<Popup x:Name="PART_Popup" Placement="Right" VerticalOffset="-5" HorizontalOffset="5" AllowsTransparency="True" IsOpen="{Binding IsSubmenuOpen, RelativeSource={RelativeSource TemplatedParent}}" PopupAnimation="Fade">
									<Border x:Name="SubMenuBorder" CornerRadius="2,4,4,4" SnapsToDevicePixels="True" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="0.70">
										<StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle"/>
									</Border>
								</Popup>
							</Grid>
						</Border>
						<ControlTemplate.Triggers>
							<Trigger Property="IsHighlighted" Value="true">
								<Setter Property="Background" TargetName="Border" Value="#555555"/>
								<Setter Property="BorderBrush" TargetName="Border" Value="#FF00BFFF"/>
							</Trigger>
							<Trigger Property="IsEnabled" Value="False">
								<Setter Property="Foreground" Value="#888888"/>
								<Setter TargetName="BlackArrow" Property="Visibility" Value="Collapsed"/>
								<Setter TargetName="GrayArrow" Property="Visibility" Value="Visible"/>
							</Trigger>
							<Trigger Property="IsEnabled" Value="True">
								<Setter TargetName="BlackArrow" Property="Visibility" Value="Visible"/>
								<Setter TargetName="GrayArrow" Property="Visibility" Value="Collapsed"/>
							</Trigger>
						</ControlTemplate.Triggers>
					</ControlTemplate>
				</Setter.Value>
			</Setter>
		</Style>
		<Style x:Key="CustomComboBoxStyle" TargetType="{x:Type ComboBox}">
			<Setter Property="Width" Value="50"/>
			<Setter Property="Height" Value="25"/>
			<Setter Property="Foreground" Value="#EEEEEE"/>
			<Setter Property="Margin" Value="0,0,5,0"/>
			<Setter Property="Template">
				<Setter.Value>
					<ControlTemplate TargetType="{x:Type ComboBox}">
						<Grid>
							<ToggleButton Name="ToggleButton" ClickMode="Press" IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}" Background="#333333" Foreground="#EEEEEE" BorderThickness="0.85" BorderBrush="#FF00BFFF">
								<TextBlock Text="{Binding SelectedItem, RelativeSource={RelativeSource TemplatedParent}}" HorizontalAlignment="Left" VerticalAlignment="Center" Foreground="#EEEEEE" Margin="5,0,0,0"/>
								<ToggleButton.Template>
									<ControlTemplate TargetType="{x:Type ToggleButton}">
										<Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
											<ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
										</Border>
										<ControlTemplate.Triggers>
											<Trigger Property="IsMouseOver" Value="True">
												<Setter Property="BorderBrush" Value="#FF00BFFF"/>
											</Trigger>
											<Trigger Property="IsChecked" Value="True">
												<Setter Property="BorderBrush" Value="#FF00BFFF"/>
											</Trigger>
										</ControlTemplate.Triggers>
									</ControlTemplate>
								</ToggleButton.Template>
							</ToggleButton>
							<Popup IsOpen="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}}" Placement="Bottom" AllowsTransparency="True" Focusable="False" PopupAnimation="Slide" Width="50">
								<Border Name="DropDownBorder" BorderBrush="#CCCCCC" BorderThickness="0.80" Background="#444444">
									<ScrollViewer MaxHeight="150" VerticalScrollBarVisibility="Hidden">
										<StackPanel IsItemsHost="True">
											<StackPanel.Resources>
												<Style TargetType="{x:Type ComboBoxItem}">
													<Setter Property="Foreground" Value="#EEEEEE"/>
													<Setter Property="Background" Value="#444444"/>
													<Setter Property="HorizontalContentAlignment" Value="Center"/>
													<Style.Triggers>
														<Trigger Property="IsHighlighted" Value="True">
															<Setter Property="Background" Value="#555555"/>
														</Trigger>
														<Trigger Property="IsSelected" Value="True">
															<Setter Property="Background" Value="#555555"/>
														</Trigger>
													</Style.Triggers>
												</Style>
											</StackPanel.Resources>
										</StackPanel>
									</ScrollViewer>
								</Border>
							</Popup>
						</Grid>
						<ControlTemplate.Triggers>
							<Trigger Property="IsMouseOver" Value="True">
								<Setter TargetName="ToggleButton" Property="BorderBrush" Value="#EEEEEE"/>
							</Trigger>
							<Trigger Property="IsDropDownOpen" Value="True">
								<Setter TargetName="DropDownBorder" Property="BorderBrush" Value="#FF00BFFF"/>
								<Setter TargetName="ToggleButton" Property="BorderBrush" Value="#EEEEEE"/>
							</Trigger>
						</ControlTemplate.Triggers>
					</ControlTemplate>
				</Setter.Value>
			</Setter>
		</Style>
	</Window.Resources>
	<Border Background="#222222" CornerRadius="5,5,5,5">
		<Grid>
			<Grid.RowDefinitions>
				<RowDefinition Height="30"/>
				<RowDefinition Height="*"/>
			</Grid.RowDefinitions>
			<Border Background="#DDDDDD" Grid.Row="0" CornerRadius="5,5,0,0">
				<Grid>
					<Grid.ColumnDefinitions>
						<ColumnDefinition Width="Auto"/>
						<ColumnDefinition Width="Auto"/>
						<ColumnDefinition Width="*"/>
						<ColumnDefinition Width="Auto"/>
					</Grid.ColumnDefinitions>
					<Image Name="WindowIconImage" Width="24" Height="24" VerticalAlignment="Center" Margin="8,0,8,0">
						<Image.Effect>
							<DropShadowEffect BlurRadius="5" ShadowDepth="1" Opacity="0.7" Direction="270" Color="Black"/>
						</Image.Effect>
					</Image>
					<TextBlock Name="TitleBar" Foreground="Black" FontWeight="Bold" VerticalAlignment="Center" HorizontalAlignment="Left" Margin="0,0,5,0" Grid.Column="1"/>
					<Grid Grid.Column="2">
						<Grid.ColumnDefinitions>
							<ColumnDefinition Width="Auto"/>
							<ColumnDefinition Width="Auto"/>
						</Grid.ColumnDefinitions>
						<TextBlock Name="externalIPt" Foreground="Black" FontWeight="Bold" VerticalAlignment="Center" Margin="0,0,5,0"/>
						<TextBlock Name="domainName" Foreground="Black" FontWeight="Bold" VerticalAlignment="Center" Margin="0,0,5,0" Grid.Column="1"/>
					</Grid>
					<StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Grid.Column="3">
						<Button Name="btnMinimize" Content="—" Width="40" Height="30" Background="Transparent" Foreground="Black" FontWeight="Bold" BorderThickness="0" Template="{StaticResource NoMouseOverButtonTemplate}"/>
						<Button Name="btnClose" Content="X" Width="40" Height="30" Background="Transparent" Foreground="Black" FontWeight="Bold" BorderThickness="0" Template="{StaticResource CloseButtonTemplate}"/>
					</StackPanel>
				</Grid>
			</Border>
			<Grid Grid.Row="1" Margin="0,0,50,0">
				<Grid Name="ScanContainer" Grid.Column="0" VerticalAlignment="Top" HorizontalAlignment="Center" Width="777" MinHeight="25" Margin="53,11,0,0">
					<Button Name="Scan" Width="777" Height="30" Background="#777777" Foreground="#000000" FontWeight="Bold" Template="{StaticResource NoMouseOverButtonTemplate}">
						<Button.ContextMenu>
							<ContextMenu Style="{StaticResource CustomContextMenuStyle}">
								<MenuItem Header="Subnet" Style="{StaticResource MainMenuItemStyle}" Name="ChangeSubnet"/>
							</ContextMenu>
						</Button.ContextMenu>
						<Button.Content>
							<StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
								<TextBlock Name="ScanButtonText" Text="Scan" Foreground="#000000" FontWeight="Bold" />
								<Image Name="scanAdminIcon" Width="16" Height="16" Margin="5,0,0,0" Visibility="Collapsed"/>
							</StackPanel>
						</Button.Content>
						<Button.BorderBrush>
							<SolidColorBrush x:Name="CycleBrush" Color="White"/>
						</Button.BorderBrush>
					</Button>
					<ProgressBar Name="Progress" Foreground="#FF00BFFF" Background="#777777" Value="0" Maximum="100" Width="777" Height="30" Visibility="Collapsed"/>
					<TextBlock Name="BarText" Foreground="#000000" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Center"/>
				</Grid>
				<ListView Name="listView" Background="#333333" FontWeight="Normal" HorizontalAlignment="Left" Height="400" Margin="19,52,-140,0" VerticalAlignment="Top" Width="860" VerticalContentAlignment="Top" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Hidden" ScrollViewer.CanContentScroll="False" AlternationCount="2">
					<ListView.ItemContainerStyle>
						<Style TargetType="{x:Type ListViewItem}">
							<Setter Property="Background" Value="Transparent" />
							<Setter Property="Foreground" Value="#EEEEEE"/>
							<Setter Property="BorderBrush" Value="Transparent"/>
							<Setter Property="BorderThickness" Value="0.70"/>
							<Setter Property="Template">
								<Setter.Value>
									<ControlTemplate TargetType="{x:Type ListViewItem}">
										<Border BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" Background="{TemplateBinding Background}">
											<GridViewRowPresenter HorizontalAlignment="Stretch" VerticalAlignment="{TemplateBinding VerticalContentAlignment}" Width="Auto" Margin="0" Content="{TemplateBinding Content}"/>
										</Border>
										<ControlTemplate.Triggers>
											<Trigger Property="ItemsControl.AlternationIndex" Value="0">
												<Setter Property="Background" Value="#111111"/>
												<Setter Property="Foreground" Value="#EEEEEE"/>
											</Trigger>
											<Trigger Property="ItemsControl.AlternationIndex" Value="1">
												<Setter Property="Background" Value="#000000"/>
												<Setter Property="Foreground" Value="#EEEEEE"/>
											</Trigger>
											<Trigger Property="IsMouseOver" Value="True">
												<Setter Property="Background" Value="#4000B7FF"/>
												<Setter Property="Foreground" Value="#EEEEEE"/>
												<Setter Property="BorderBrush" Value="#FF00BFFF"/>
											</Trigger>
											<MultiTrigger>
												<MultiTrigger.Conditions>
													<Condition Property="IsSelected" Value="true"/>
													<Condition Property="Selector.IsSelectionActive" Value="true"/>
												</MultiTrigger.Conditions>
												<Setter Property="Background" Value="#4000B7FF"/>
												<Setter Property="Foreground" Value="#EEEEEE"/>
												<Setter Property="FontWeight" Value="Bold"/>
												<Setter Property="BorderBrush" Value="#FF00BFFF"/>
											</MultiTrigger>
										</ControlTemplate.Triggers>
									</ControlTemplate>
								</Setter.Value>
							</Setter>
						</Style>
					</ListView.ItemContainerStyle>
					<ListView.View>
						<GridView>
							<GridViewColumn Header="MAC Address" DisplayMemberBinding="{Binding MACaddress}" Width="150" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
							<GridViewColumn Header="Vendor" DisplayMemberBinding="{Binding Vendor}" Width="230" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
							<GridViewColumn Header="IP Address" Width="190" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}">
								<GridViewColumn.CellTemplate>
									<DataTemplate>
										<StackPanel Orientation="Horizontal">
											<ContentControl Content="{Binding PingImage}" Width="16" Height="16" Margin="0,0,10,0"/>
											<TextBlock Text="{Binding IPaddress}"/>
										</StackPanel>
									</DataTemplate>
								</GridViewColumn.CellTemplate>
							</GridViewColumn>
							<GridViewColumn Header="Host Name" DisplayMemberBinding="{Binding HostName}" Width="284" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
						</GridView>
					</ListView.View>
					<ListView.ContextMenu>
						<ContextMenu Style="{StaticResource CustomContextMenuStyle}">
							<MenuItem Header="    Export    " Name="ExportContext" Style="{StaticResource MainMenuItemStyle}">
								<MenuItem Header="   HTML   " Name="ExportToHTML" Style="{StaticResource CustomMenuItemStyle}"/>
								<MenuItem Header="   CSV    " Name="ExportToCSV" Style="{StaticResource CustomMenuItemStyle}"/>
								<MenuItem Header="   Text   " Name="ExportToText" Style="{StaticResource CustomMenuItemStyle}"/>
							</MenuItem>
						</ContextMenu>
					</ListView.ContextMenu>
				</ListView>
				<Canvas Name="PopupCanvas" Background="#222222" Visibility="Hidden" Width="350" Height="240" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="53,40,0,0">
					<Border Name="PopupBorder" Width="350" Height="240" BorderThickness="0.70">
						<Border.BorderBrush>
							<SolidColorBrush Color="#CCCCCC"/>
						</Border.BorderBrush>
						<Grid Background="Transparent">
							<Grid.RowDefinitions>
								<RowDefinition Height="Auto"/>
								<RowDefinition Height="*"/>
							</Grid.RowDefinitions>
							<StackPanel Margin="10" Grid.Row="0">
								<StackPanel Orientation="Horizontal">
									<ContentControl Name="pingStatusImage" Width="12" Height="12" Margin="15,10,10,0"/>
									<TextBlock Name="pingStatusText" FontSize="14" Foreground="#EEEEEE" FontWeight="Bold" VerticalAlignment="Center" Margin="0,8,0,0"/>
								</StackPanel>
							</StackPanel>
							<StackPanel Margin="10" Grid.Row="1">
								<TextBlock Name="pHost" FontSize="14" Foreground="#EEEEEE" FontWeight="Bold" Margin="15,0,0,0"/>
								<TextBlock Name="pIP" FontSize="14" Foreground="#EEEEEE" Margin="15,0,0,0" />
								<TextBlock Name="pMAC" FontSize="14" Foreground="#EEEEEE" Margin="15,0,0,0" />
								<TextBlock Name="pVendor" FontSize="14" Foreground="#EEEEEE" Margin="15,0,0,0" />
								<StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,35,0,0">
									<Button Name="btnRDP" Width="40" Height="32" ToolTip="Connect via RDP" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="False" Background="Transparent" Margin="0,0,25,0" Template="{StaticResource NoMouseOverButtonTemplate}">
										<Button.Effect>
											<DropShadowEffect ShadowDepth="5" BlurRadius="5" Color="Black" Direction="270"/>
										</Button.Effect>
										<Button.Resources>
											<Storyboard x:Key="mouseEnterAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="-3" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="10" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="10" Duration="0:0:0.2"/>
											</Storyboard>
											<Storyboard x:Key="mouseLeaveAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="0" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="5" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="5" Duration="0:0:0.2"/>
											</Storyboard>
										</Button.Resources>
										<Button.RenderTransform>
											<TranslateTransform/>
										</Button.RenderTransform>
									</Button>
									<Button Name="btnWebInterface" Width="40" Height="32" ToolTip="Connect via Web Interface" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="False" Background="Transparent" Margin="0,0,25,0" Template="{StaticResource NoMouseOverButtonTemplate}">
										<Button.Effect>
											<DropShadowEffect ShadowDepth="5" BlurRadius="5" Color="Black" Direction="270"/>
										</Button.Effect>
										<Button.Resources>
											<Storyboard x:Key="mouseEnterAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="-3" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="10" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="10" Duration="0:0:0.2"/>
											</Storyboard>
											<Storyboard x:Key="mouseLeaveAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="0" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="5" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="5" Duration="0:0:0.2"/>
											</Storyboard>
										</Button.Resources>
										<Button.RenderTransform>
											<TranslateTransform/>
										</Button.RenderTransform>
									</Button>
									<Button Name="btnShare" Width="40" Height="32" ToolTip="Connect via Share" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="False" Background="Transparent" Template="{StaticResource NoMouseOverButtonTemplate}">
										<Button.Effect>
											<DropShadowEffect ShadowDepth="5" BlurRadius="5" Color="Black" Direction="270"/>
										</Button.Effect>
										<Button.Resources>
											<Storyboard x:Key="mouseEnterAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="-3" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="10" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="10" Duration="0:0:0.2"/>
											</Storyboard>
											<Storyboard x:Key="mouseLeaveAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="0" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="5" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="5" Duration="0:0:0.2"/>
											</Storyboard>
										</Button.Resources>
										<Button.RenderTransform>
											<TranslateTransform/>
										</Button.RenderTransform>
									</Button>
									<Button Name="btnNone" Width="40" Height="32" ToolTip="No Connections Found" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="False" Background="Transparent" Template="{StaticResource NoMouseOverButtonTemplate}">
										<Button.Effect>
											<DropShadowEffect ShadowDepth="5" BlurRadius="5" Color="Black" Direction="270"/>
										</Button.Effect>
										<Button.Resources>
											<Storyboard x:Key="mouseEnterAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="-3" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="10" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="10" Duration="0:0:0.2"/>
											</Storyboard>
											<Storyboard x:Key="mouseLeaveAnimation">
												<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="0" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="5" Duration="0:0:0.2"/>
												<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="5" Duration="0:0:0.2"/>
											</Storyboard>
										</Button.Resources>
										<Button.RenderTransform>
											<TranslateTransform/>
										</Button.RenderTransform>
									</Button>
								</StackPanel>
							</StackPanel>
							<Button Name="pCloseButton" Background="#111111" Foreground="#EEEEEE" BorderThickness="0" Content="X" Margin="300,10,10,10" Height="18" Width="22" Template="{StaticResource NoMouseOverButtonTemplate}" Panel.ZIndex="1"/>
						</Grid>
					</Border>
					<Canvas.ContextMenu>
						<ContextMenu Style="{StaticResource CustomContextMenuStyle}">
							<MenuItem Header="    Copy    " Style="{StaticResource MainMenuItemStyle}">
								<MenuItem Header="   IP Address  " Name="PopupContextCopyIP" Style="{StaticResource CustomMenuItemStyle}"/>
								<MenuItem Header="   Hostname    " Name="PopupContextCopyHostname" Style="{StaticResource CustomMenuItemStyle}"/>
								<MenuItem Header="   MAC Address " Name="PopupContextCopyMAC" Style="{StaticResource CustomMenuItemStyle}"/>
								<MenuItem Header="   Vendor      " Name="PopupContextCopyVendor" Style="{StaticResource CustomMenuItemStyle}"/>
								<Separator Background="#111111"/>
								<MenuItem Header="   All         " Name="PopupContextCopyAll" Style="{StaticResource CustomMenuItemStyle}"/>
							</MenuItem>
						</ContextMenu>
					</Canvas.ContextMenu>
				</Canvas>
				<Canvas Name="PopupCanvas2" Background="#222222" Visibility="Hidden" Width="330" Height="220" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="53,40,0,0">
					<Border Name="PopupBorder2" Width="330" Height="220" BorderThickness="0.70" CornerRadius="5" Background="#333333" Opacity="0.95">
						<Border.BorderBrush>
							<SolidColorBrush Color="#CCCCCC"/>
						</Border.BorderBrush>
						<Border.RenderTransform>
							<TransformGroup>
								<ScaleTransform/>
								<SkewTransform/>
								<RotateTransform/>
								<TranslateTransform/>
							</TransformGroup>
						</Border.RenderTransform>
						<Grid>
							<Grid.RowDefinitions>
								<RowDefinition Height="Auto"/>
								<RowDefinition Height="*"/>
								<RowDefinition Height="Auto"/>
								<RowDefinition Height="Auto"/>
							</Grid.RowDefinitions>
							<TextBlock Name="PopupTitle2" HorizontalAlignment="Center" Margin="0,10,0,0" FontSize="14" Foreground="#EEEEEE" FontWeight="Bold" Grid.Row="0"/>
							<TextBlock Name="PopupText2" TextWrapping="Wrap" Margin="10,60,10,0" FontSize="14" Foreground="#EEEEEE" FontWeight="Bold" VerticalAlignment="Top" HorizontalAlignment="Center" Grid.Row="1" Visibility="Visible"/>
							<StackPanel Name="SubnetInput" Grid.Row="1" Margin="10,60,10,0" Visibility="Collapsed">
								<StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
									<TextBlock Text="Subnet" FontSize="14" Foreground="#EEEEEE" Margin="0,2,5,5"/>
									<ComboBox Name="subnetOctet1" Style="{StaticResource CustomComboBoxStyle}"/>
									<ComboBox Name="subnetOctet2" Style="{StaticResource CustomComboBoxStyle}"/>
									<ComboBox Name="subnetOctet3" Style="{StaticResource CustomComboBoxStyle}"/>
									<TextBlock Text="1-254" FontSize="14" Foreground="#EEEEEE" Margin="0,2,0,0"/>
								</StackPanel>
								<Button Name="btnReset" Width="24" Height="24" ToolTip="Reset Subnet" Margin="0,12,0,0" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="True" Background="Transparent" Template="{StaticResource NoMouseOverButtonTemplate}">
									<Button.Effect>
										<DropShadowEffect ShadowDepth="5" BlurRadius="5" Color="Black" Direction="270"/>
									</Button.Effect>
									<Button.Resources>
										<Storyboard x:Key="mouseEnterAnimation">
											<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="-2" Duration="0:0:0.2"/>
											<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="6" Duration="0:0:0.2"/>
											<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="6" Duration="0:0:0.2"/>
										</Storyboard>
										<Storyboard x:Key="mouseLeaveAnimation">
											<DoubleAnimation Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)" To="0" Duration="0:0:0.2"/>
											<DoubleAnimation Storyboard.TargetProperty="Effect.ShadowDepth" To="3" Duration="0:0:0.2"/>
											<DoubleAnimation Storyboard.TargetProperty="Effect.BlurRadius" To="3" Duration="0:0:0.2"/>
										</Storyboard>
									</Button.Resources>
									<Button.RenderTransform>
										<TranslateTransform/>
									</Button.RenderTransform>
								</Button>
							</StackPanel>
							<Button Name="pCloseButton2" Content="X" Background="#111111" Foreground="#EEEEEE" BorderThickness="0" HorizontalAlignment="Right" Margin="0,5,5,5" Height="18" Width="22" Grid.Row="0" Template="{StaticResource NoMouseOverButtonTemplate}"/>
							<StackPanel Name="ButtonStackPanel2" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,0,0,10" Grid.Row="2">
								<Button Name="btnOK2" Content="OK" Margin="5,10,5,10" Background="#111111" Foreground="#EEEEEE" Width="75" Height="25" Template="{StaticResource NoMouseOverButtonTemplate}"/>
							</StackPanel>
						</Grid>
					</Border>
				</Canvas>
			</Grid>
		</Grid>
	</Border>
	<Window.Triggers>
		<EventTrigger RoutedEvent="Window.Loaded">
			<BeginStoryboard>
				<Storyboard>
					<ColorAnimationUsingKeyFrames Storyboard.TargetName="CycleBrush" Storyboard.TargetProperty="Color" RepeatBehavior="Forever" Duration="0:0:6">
						<LinearColorKeyFrame Value="#CCCCCC" KeyTime="0:0:0"/>
						<LinearColorKeyFrame Value="#FF00BFFF" KeyTime="0:0:3"/>
						<LinearColorKeyFrame Value="#CCCCCC" KeyTime="0:0:6"/>
					</ColorAnimationUsingKeyFrames>
					<ColorAnimationUsingKeyFrames Storyboard.TargetName="PopupBorder" Storyboard.TargetProperty="BorderBrush.Color" RepeatBehavior="Forever" Duration="0:0:6">
						<LinearColorKeyFrame Value="#CCCCCC" KeyTime="0:0:0"/>
						<LinearColorKeyFrame Value="#FF00BFFF" KeyTime="0:0:3"/>
						<LinearColorKeyFrame Value="#CCCCCC" KeyTime="0:0:6"/>
					</ColorAnimationUsingKeyFrames>
					<ColorAnimationUsingKeyFrames Storyboard.TargetName="PopupBorder2" Storyboard.TargetProperty="BorderBrush.Color" RepeatBehavior="Forever" Duration="0:0:6">
						<LinearColorKeyFrame Value="#CCCCCC" KeyTime="0:0:0"/>
						<LinearColorKeyFrame Value="#FF00BFFF" KeyTime="0:0:3"/>
						<LinearColorKeyFrame Value="#CCCCCC" KeyTime="0:0:6"/>
					</ColorAnimationUsingKeyFrames>
				</Storyboard>
			</BeginStoryboard>
		</EventTrigger>
	</Window.Triggers>
	<Window.TaskbarItemInfo>
		<TaskbarItemInfo/>
	</Window.TaskbarItemInfo>
</Window>
'@

# Load XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
try{$Main = [Windows.Markup.XamlReader]::Load( $reader )}
catch{$shell = New-Object -ComObject Wscript.Shell; $shell.Popup("$_",0,'XAML ERROR:',0x0) | Out-Null; Exit}

# Store Form Objects In PowerShell
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "$($_.Name)" -Value $Main.FindName($_.Name)}

# Set Title
$Main.Title = "$AppId"
$titleBar.Text = "$AppId"

$Main.Add_Closing({
	# Force close any running jobs
	Get-Job | Remove-Job -Force
	# Clean up RunspacePool if it exists
	if ($RunspacePool) {
		try {
			$RunspacePool.Close()
		}
		catch {
			#TO-DO Add logging, eg: Add-Content -Path "C:\path\to\logfile.txt" -Value "Error closing RunspacePool: $_"
			$null = $_
		}
		finally {
			$RunspacePool.Dispose()
		}
	}
	$Main.Add_Closed({
		[Environment]::Exit(0)
	})
})

$Main.Add_Loaded({
	$Main.Dispatcher.Invoke([action]{
		$Main.Activate()
	}, [Windows.Threading.DispatcherPriority]::Background)
})

# Center main window
$screen = [System.Windows.SystemParameters]::WorkArea
$windowLeft = ($screen.Width - $Main.Width) / 2
$windowTop = ($screen.Height - $Main.Height) / 2
$Main.Left = $windowLeft
$Main.Top = $windowTop

$btnMinimize.Add_Click({
	$Main.WindowState = [System.Windows.WindowState]::Minimized
})

$btnMinimize.Add_MouseEnter({
	$btnMinimize.Background='#BBBBBB'
})
$btnMinimize.Add_MouseLeave({
	$btnMinimize.Background='#DDDDDD'
})

$btnClose.Add_Click({
	$Main.Close()
})

$btnClose.Add_MouseEnter({
	$btnClose.Background='#ff0000'
})
$btnClose.Add_MouseLeave({
	$btnClose.Background='#DDDDDD'
})

$Main.Add_MouseLeftButtonDown({
	$Main.DragMove()
})

$pCloseButton.Add_Click({
	$PopupCanvas.Visibility = 'Hidden'
})

$pCloseButton.Add_MouseEnter({
	$pCloseButton.Background='#ff0000'
})
$pCloseButton.Add_MouseLeave({
	$pCloseButton.Background='#111111'
})

$pCloseButton2.Add_Click({
	$PopupCanvas2.Visibility = 'Hidden'
})

$pCloseButton2.Add_MouseEnter({
	$pCloseButton2.Background='#ff0000'
})
$pCloseButton2.Add_MouseLeave({
	$pCloseButton2.Background='#111111'
})

# Message popup
function Show-Popup2 {
	param (
		[string]$Message,
		[string]$Title = 'Info',
		[bool]$IsSubnetPopup = $false
	)

	$PopupTitle2.Text = $Title
	$PopupText2.Text = $Message

	if ($IsSubnetPopup) {
		$SubnetInput.Visibility = 'Visible'
		$PopupText2.Visibility = 'Collapsed'
		$btnOK2.Content = 'OK'
	} else {
		$SubnetInput.Visibility = 'Collapsed'
		$PopupText2.Visibility = 'Visible'
		$btnOK2.Content = 'OK'
	}

	$centerX = ($Main.ActualWidth - $PopupBorder2.ActualWidth) / 2
	$centerY = ($Main.ActualHeight - $PopupBorder2.ActualHeight) / 2
	$PopupCanvas2.SetValue([System.Windows.Controls.Canvas]::LeftProperty, [System.Windows.Controls.Canvas]::GetLeft($listView) + 10)
	$PopupCanvas2.SetValue([System.Windows.Controls.Canvas]::TopProperty, [System.Windows.Controls.Canvas]::GetTop($listView) + 10)

	$PopupCanvas2.Visibility = 'Visible'
}

# Define icons
$icons = @(
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 18; ElementName = "WindowIcon"; Type = "Window"},
	@{File = 'C:\Windows\System32\imageres.dll'; Index = 73; ElementName = "scanAdminIcon"; Type = "Image"},
	@{File = 'C:\Windows\System32\mstscax.dll'; Index = 0; ElementName = "btnRDP"; Type = "Button"},
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 13; ElementName = "btnWebInterface"; Type = "Button"},
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 266; ElementName = "btnShare"; Type = "Button"},
	@{File = 'C:\Windows\System32\ieframe.dll'; Index = 75; ElementName = "btnNone"; Type = "Button"},
	@{File = 'C:\Windows\System32\imageres.dll'; Index = 229; ElementName = "btnReset"; Type = "Button"}
)

# Extract and set icons
foreach ($icon in $icons) {
	$extractedIcon = [System.IconExtractor]::Extract($icon.File, $icon.Index, $true)
	if ($extractedIcon) {
		$bitmapSource = [System.IconExtractor]::IconToBitmapSource($extractedIcon)
		$element = $Main.FindName($icon.ElementName)

		switch ($icon.Type) {
			"Window" {
				$Main.Icon = $bitmapSource
				$Main.TaskbarItemInfo.Overlay = $bitmapSource
				$Main.TaskbarItemInfo.Description = $AppId
				($Main.FindName('WindowIconImage')).Source = $bitmapSource
				($Main.FindName('WindowIconImage')).SetValue([System.Windows.Media.RenderOptions]::BitmapScalingModeProperty, [System.Windows.Media.BitmapScalingMode]::HighQuality)
			}
			"Image" {
				$element.Source = $bitmapSource
				$element.SetValue([System.Windows.Media.RenderOptions]::BitmapScalingModeProperty, [System.Windows.Media.BitmapScalingMode]::HighQuality)
			}
			"Button" {
				$image = New-Object System.Windows.Controls.Image -Property @{
					Source = $bitmapSource;
					Width = if($icon.ElementName -eq "btnReset"){16} else {24};
					Height = if($icon.ElementName -eq "btnReset"){16} else {24};
				}
				$image.SetValue([System.Windows.Media.RenderOptions]::BitmapScalingModeProperty, [System.Windows.Media.BitmapScalingMode]::HighQuality)
				$element.Content = $image
			}
		}
	}
}

# Populate the ComboBoxes
function Initialize-IPCombo {
	param($comboBox)
	for ($i = 0; $i -le 255; $i++) {
		$comboBox.Items.Add($i)
	}
	$comboBox.SelectedIndex = 0
}

# Initialize Comboboxes
@('subnetOctet1', 'subnetOctet2', 'subnetOctet3') | ForEach-Object {
	Initialize-IPCombo -comboBox ($Main.FindName($_))
}

$ChangeSubnet.Add_Click({
	$parts = $global:gatewayPrefix -split '\.'
	if ($parts.Length -ge 3) {
		$subnetOctet1.SelectedItem = [int]$parts[0]
		$subnetOctet2.SelectedItem = [int]$parts[1]
		$subnetOctet3.SelectedItem = [int]$parts[2]
	} else {
		$subnetOctet1.SelectedItem = 192
		$subnetOctet2.SelectedItem = 168
		$subnetOctet3.SelectedItem = 1
	}
	Show-Popup2 -Title "Segment Exploration" -IsSubnetPopup $true
})

$btnReset.Add_Click({
	if ($originalGatewayPrefix) {
		$parts = $originalGatewayPrefix -split '\.'
		if ($parts.Length -ge 3) {
			$subnetOctet1.SelectedItem = [int]$parts[0]
			$subnetOctet2.SelectedItem = [int]$parts[1]
			$subnetOctet3.SelectedItem = [int]$parts[2]
			$global:gatewayPrefix = $originalGatewayPrefix
		}
	}
})

$btnReset.Add_MouseEnter({
	$btnReset.FindResource("mouseEnterAnimation").Begin($btnReset)
})

$btnReset.Add_MouseLeave({
	$btnReset.FindResource("mouseLeaveAnimation").Begin($btnReset)
})

$btnOK2.Add_Click({
	if ($SubnetInput.Visibility -eq 'Visible') {
		$global:gatewayPrefix = "{0}.{1}.{2}." -f $subnetOctet1.SelectedItem, $subnetOctet2.SelectedItem, $subnetOctet3.SelectedItem
	}
	if ($global:gatewayPrefix -ne $originalGatewayPrefix) {
		$scanButtonText.Text = 'Custom Scan'
	} else {
		$scanButtonText.Text = 'Scan'
	}
	$PopupCanvas2.Visibility = 'Hidden'

})

$btnOK2.Add_MouseEnter({
	$btnOK2.Foreground='#000000'
	$btnOK2.Background='#CCCCCC'
})
$btnOK2.Add_MouseLeave({
	$btnOK2.Foreground='#EEEEEE'
	$btnOK2.Background='#111111'
})

$btnRDP.Add_Click({
	&mstsc /v:$tryToConnect
})

$btnRDP.Add_MouseEnter({
	$btnRDP.FindResource("mouseEnterAnimation").Begin($btnRDP)
})

$btnRDP.Add_MouseLeave({
	$btnRDP.FindResource("mouseLeaveAnimation").Begin($btnRDP)
})

$btnWebInterface.Add_Click({
	# Priority order: HTTP/HTTPS
	if($script:httpAvailable -eq 1){
		Start-Process "`"http://$tryToConnect`""
	} else {
		Start-Process "`"https://$tryToConnect`""
	}
})

$btnWebInterface.Add_MouseEnter({
	$btnWebInterface.FindResource("mouseEnterAnimation").Begin($btnWebInterface)
})

$btnWebInterface.Add_MouseLeave({
	$btnWebInterface.FindResource("mouseLeaveAnimation").Begin($btnWebInterface)
})

$btnShare.Add_Click({
	&explorer "`"\\$tryToConnect`""
})

$btnShare.Add_MouseEnter({
	$btnShare.FindResource("mouseEnterAnimation").Begin($btnShare)
})

$btnShare.Add_MouseLeave({
	$btnShare.FindResource("mouseLeaveAnimation").Begin($btnShare)
})

$btnNone.Add_MouseEnter({
	$btnNone.FindResource("mouseEnterAnimation").Begin($btnNone)
})

$btnNone.Add_MouseLeave({
	$btnNone.FindResource("mouseLeaveAnimation").Begin($btnNone)
})

# Export List in HTML format
$ExportToHTML.Add_Click({
	$saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
	$saveFileDialog.Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
	$saveFileDialog.FileName = "Network_Scan_Results"
	if ($saveFileDialog.ShowDialog() -eq "OK") {
		$path = $saveFileDialog.FileName
		try {
			# Create HTML content with header
			$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
	<title>Network Scan Results</title>
	<style>
		table, th, td { border: 1px solid black; border-collapse: collapse; padding: 5px; }
		th { background-color: #f2f2f2; }
		h1, p { margin: 0; padding: 0; }
		p { margin-bottom: 2px; }
		.info-block { margin-bottom: 20px; }
	</style>
</head>
<body>
	<h1>Network Scan Results</h1><br>
	<div class="info-block">
		<p><strong>External IP:</strong> $global:externalIP</p>
		<p><strong>Domain:</strong> $global:domain</p>
		<p><strong>Date/Time:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
	</div>
	<table>
		<tr>
			<th>MAC Address</th>
			<th>Vendor</th>
			<th>IP Address</th>
			<th>Host Name</th>
		</tr>
"@
			$listView.Items | ForEach-Object {
				$htmlContent += @"
		<tr>
			<td>$($_.MACaddress)</td>
			<td>$($_.Vendor)</td>
			<td>$($_.IPaddress)</td>
			<td>$($_.HostName.Replace(' (This Device)',''))</td>
		</tr>
"@
			}
			$htmlContent += @"
	</table>
</body>
</html>
"@

			# Write HTML to file
			[System.IO.File]::WriteAllText($path, $htmlContent)
			Show-Popup2 -Message 'Export to HTML completed successfully!' -Title 'Export:'
		}
		catch {
			Show-Popup2 -Message "Error during export: $_" -Title 'ERROR:'
		}
	}
})

# Export List in CSV format
$ExportToCSV.Add_Click({
	$saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
	$saveFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
	$saveFileDialog.FileName = "Network_Scan_Results"
	if ($saveFileDialog.ShowDialog() -eq "OK") {
		$path = $saveFileDialog.FileName
		try {
			# CSV header
			$csvHeader = "External IP,Domain,Date/Time`r`n"
			$csvHeader += "$global:externalIP,$global:domain,$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")"
			$csvContent = $listView.Items | ForEach-Object {
				"`r`n$($_.MACaddress),$($_.Vendor),$($_.IPaddress),$($_.HostName.Replace(' (This Device)',''))"
			}
			[System.IO.File]::WriteAllLines($path, ($csvHeader + $csvContent))
			Show-Popup2 -Message 'Export to CSV completed successfully!' -Title 'Export:'
		}
		catch {
			Show-Popup2 -Message "Error during export: $_" -Title 'ERROR:'
		}
	}
})

# Export List in TXT format
$ExportToText.Add_Click({
	$saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
	$saveFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
	$saveFileDialog.FileName = "Network_Scan_Results"
	if ($saveFileDialog.ShowDialog() -eq "OK") {
		$path = $saveFileDialog.FileName
		try {
			# TXT header
			$textContent = @"
NETWORK SCAN RESULTS

EXTERNAL IP : $global:externalIP
DOMAIN      : $global:domain
DATE/TIME   : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

--------------------------------------
"@
			$textContent += $listView.Items | ForEach-Object {
@"

MAC      : $($_.MACaddress)
Vendor   : $($_.Vendor)
IP       : $($_.IPaddress)
Hostname : $($_.HostName.Replace(' (This Device)',''))
--------------------------------------
"@
			}
			[System.IO.File]::WriteAllText($path, $textContent)
			Show-Popup2 -Message 'Export to Text completed successfully!' -Title 'Export:'
		}
		catch {
			Show-Popup2 -Message "Error during export: $_" -Title 'ERROR:'
		}
	}
})

# Add listView column header click capture
$ListView.AddHandler(
	[System.Windows.Controls.GridViewColumnHeader]::ClickEvent,
	[System.Windows.RoutedEventHandler]$listViewSortColumn
)

# Find and assign Hostname column from listView to control width when scrollbar is present
$hostNameColumn = ($listView.View.Columns | Where-Object {$_.Header -eq "Host Name"})

$listView.Add_MouseDoubleClick({
	if($listView.SelectedItems.Count -gt 0){
		if($listView.SelectedItems.HostName -ne 'Unable to Resolve'){
			$selectedHost = $listView.SelectedItems.HostName
		} else {
			$selectedHost = $listView.SelectedItems.IPaddress
		}
		CheckConnectivity -selectedhost "$selectedHost"
		$selectedItem = $listView.SelectedItems[0]
		$pMAC.Text = "MAC: " + $selectedItem.MACaddress
		$pVendor.Text = "Vendor: " + $selectedItem.Vendor
		$pIP.Text = "IP: " + $selectedItem.IPaddress
		$pHost.Text = "Host: " + $selectedItem.HostName.Replace(' (This Device)','')
		$PopupCanvas.SetValue([System.Windows.Controls.Canvas]::LeftProperty, [System.Windows.Controls.Canvas]::GetLeft($listView) + 10)
		$PopupCanvas.SetValue([System.Windows.Controls.Canvas]::TopProperty, [System.Windows.Controls.Canvas]::GetTop($listView) + 10)
		$PopupCanvas.Visibility = 'Visible'
	}
})

$listView.Add_MouseLeftButtonDown({
	$listView.SelectedItems.Clear()
})

# Single item pop-up context menu, IP Address to clipboard
$PopupContextCopyIP_Click = {
	if ($PopupCanvas.Visibility -eq 'Visible') {
		$ipText = $pIP.Text -replace 'IP: '
		Set-Clipboard -Value $ipText
		Show-Popup2 -Message 'IP Address copied to clipboard!' -Title 'Info:'
	} else {
		Show-Popup2 -Message 'No item available to copy IP Address from!' -Title 'Warning:'
	}
}
$PopupContextCopyIP.Add_Click($PopupContextCopyIP_Click)

# Single item pop-up context menu, Hostname to clipboard
$PopupContextCopyHostname_Click = {
	if ($PopupCanvas.Visibility -eq 'Visible') {
		$hostText = $pHost.Text -replace 'Host: '
		Set-Clipboard -Value $hostText
		Show-Popup2 -Message 'Hostname copied to clipboard!' -Title 'Info:'
	} else {
		Show-Popup2 -Message 'No item available to copy Hostname from!' -Title 'Warning:'
	}
}
$PopupContextCopyHostname.Add_Click($PopupContextCopyHostname_Click)

# Single item pop-up context menu, MAC Address to clipboard
$PopupContextCopyMAC_Click = {
	if ($PopupCanvas.Visibility -eq 'Visible') {
		$macText = $pMAC.Text -replace 'MAC: '
		Set-Clipboard -Value $macText
		Show-Popup2 -Message 'MAC Address copied to clipboard!' -Title 'Info:'
	} else {
		Show-Popup2 -Message 'No item available to copy MAC Address from!' -Title 'Warning:'
	}
}
$PopupContextCopyMAC.Add_Click($PopupContextCopyMAC_Click)

# Single item pop-up context menu, Vendor to clipboard
$PopupContextCopyVendor_Click = {
	if ($PopupCanvas.Visibility -eq 'Visible') {
		$vendorText = $pVendor.Text -replace 'Vendor: '
		Set-Clipboard -Value $vendorText
		Show-Popup2 -Message 'Vendor copied to clipboard!' -Title 'Info:'
	} else {
		Show-Popup2 -Message 'No item available to copy Vendor from!' -Title 'Warning:'
	}
}
$PopupContextCopyVendor.Add_Click($PopupContextCopyVendor_Click)

# Single item pop-up context menu, All details to clipboard
$PopupContextCopyAll_Click = {
	if ($PopupCanvas.Visibility -eq 'Visible') {
		$hostText = $pHost.Text -replace 'Host: '
		$ipText = $pIP.Text -replace 'IP: '
		$macText = $pMAC.Text -replace 'MAC: '
		$vendorText = $pVendor.Text -replace 'Vendor: '
		$details = "Host: $hostText`nIP: $ipText`nMAC: $macText`nVendor: $vendorText"
		Set-Clipboard -Value $details
		Show-Popup2 -Message 'All details copied to clipboard!' -Title 'Info:'
	} else {
		Show-Popup2 -Message 'No item available to copy details from!' -Title 'Warning:'
	}
}
$PopupContextCopyAll.Add_Click($PopupContextCopyAll_Click)

# Clear CTRL key value
$global:CtrlIsDown = $false

# KeyDown event handler
$Main.Add_KeyDown({
	if ($_.Key -eq 'LeftCtrl' -or $_.Key -eq 'RightCtrl') {
		$global:CtrlIsDown = $true
		if($Scan.IsEnabled){
			$scanButtonText.Text = 'Clear ARP cache'
			$scanAdminIcon.Visibility = 'Visible'
		}
	}
})

# KeyUp event handler
$Main.Add_KeyUp({
	if ($_.Key -eq 'LeftCtrl' -or $_.Key -eq 'RightCtrl') {
		$global:CtrlIsDown = $false
		if($Scan.IsEnabled){
			if ($global:gatewayPrefix -ne $originalGatewayPrefix) {
				$scanButtonText.Text = 'Custom Scan'
			} else {
				$scanButtonText.Text = 'Scan'
			}
			$scanAdminIcon.Visibility = 'Collapsed'
		}
	}
})

# Wait for background jobs to finish with progress tracking
function TrackProgress {
	$totalJobs = (($listView.Items.Count - 2) * 2)
	$completedJobs = 0

	do {
		$hostJobsLeft = 0
		$vendorJobsLeft = 0

		foreach ($item in $listView.Items) {
			if ($item.HostName -eq "Resolving...") {
				$hostJobsLeft++
			} else {
				$completedJobs++
			}
			if ($item.Vendor -eq "Identifying...") {
				$vendorJobsLeft++
			} else {
				if ($item.HostName -ne "Resolving...") {
					$completedJobs++
				}
			}
		}

		# Adjust completedJobs to avoid double-counting
		$completedJobs = [math]::Floor($completedJobs / 2)
		$completedPercentage = if ($totalJobs -gt 0) { ($completedJobs / $totalJobs) * 100 } else { 0 }
		Update-Progress ([math]::Min(100, $completedPercentage)) 'Identifying Devices'
		if (($hostJobsLeft + $vendorJobsLeft) -ge 1) {
			Start-Sleep -Milliseconds 250
		}
	} while (($hostJobsLeft + $vendorJobsLeft) -ge 1)
}

# Ensure clean ListView
if($listview.Items){
	$listview.Items.Clear()
}

$ExportContext.IsEnabled = $false

# Define Scan Button Actions
$Scan.Add_MouseEnter({
	$Scan.Background = '#EEEEEE'
})

$Scan.Add_MouseLeave({
	$Scan.Background = '#777777'
})

$Scan.Add_Click({
	if($PopupCanvas.Visibility -eq 'Visible') {
		$PopupCanvas.Visibility = 'Hidden'
	}
	if($PopupCanvas2.Visibility -eq 'Visible') {
		$PopupCanvas2.Visibility = 'Hidden'
	}
	# If CTRL key is held while clicking the Scan button, offer to clear ARP cache as Admin prior to Scan process
	if ($global:CtrlIsDown) {
		$Scan.IsEnabled = $false
		$osInfo = Get-CimInstance Win32_OperatingSystem
		if ($osInfo.Caption -match "Server") {
			Show-Popup2 -Message 'This option is not available for Windows Servers. Please clear your ARP Cache manually.' -Title 'Restricted Feature:'
		} else {
			try{
				Start-Process -Verb RunAs powershell -WindowStyle Minimized -ArgumentList '-Command "& {Remove-NetNeighbor -InterfaceAlias * -Confirm:$false}"'
				$listView.Items.Clear()
				Show-Popup2 -Message 'Cached peer list cleared...' -Title 'List Cleared:'
			}catch{
				Show-Popup2 -Message 'No action was taken...' -Title 'Process Aborted:'
			}
		}
		if ($global:gatewayPrefix -ne $originalGatewayPrefix) {
			$scanButtonText.Text = 'Custom Scan'
		} else {
			$scanButtonText.Text = 'Scan'
		}
		$scanAdminIcon.Visibility = 'Collapsed'
		$Scan.IsEnabled = $true
		$global:CtrlIsDown = $false
	} else {
		$Scan.IsEnabled = $false
		# Make ProgressBar visible, hide Button
		$Scan.Visibility = 'Collapsed'
		$Progress.Visibility = 'Visible'
		$Progress.Value = 0
		$BarText.Text = 'Initializing'
		$listView.Items.Clear()
		$ExportContext.IsEnabled = $false
		$hostNameColumn.Width = 284
		Update-uiMain
		Get-HostInfo -gateway $global:gateway -gatewayPrefix $global:gatewayPrefix -originalGatewayPrefix $originalGatewayPrefix
		$externalIPt.Text = "`- `[ External IP: $externalIP `]"
		$domainName.Text = "`- `[ Domain: $domain `]"
		Update-uiMain
		Scan-Subnet
		List-Machines
		processVendors
		processHostnames
		TrackProgress
		# Hide ProgressBar, show button
		$Progress.Visibility = 'Collapsed'
		$Scan.Visibility = 'Visible'
		$BarText.Text = ''
		$Scan.IsEnabled = $true
		$Progress.Value = 0
		if ($listView.Items.Count -eq 0) {
			$ExportContext.IsEnabled = $false
		} else {
			$ExportContext.IsEnabled = $true
		}
		Update-uiMain
		$global:CtrlIsDown = $false
	}
})

# Show Window
$Main.ShowDialog() | out-null