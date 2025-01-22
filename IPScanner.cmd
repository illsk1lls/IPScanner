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

# Get Host Info
function Get-HostInfo {
	# Get Hostname
	$global:hostName = [System.Net.Dns]::GetHostName()

	# Check internet connection and get external IP
	$ProgressPreference = 'SilentlyContinue'
	try {
		$ncsiCheck = Invoke-RestMethod "http://www.msftncsi.com/ncsi.txt"
		if ($ncsiCheck -eq "Microsoft NCSI") {
			$global:externalIP = Invoke-RestMethod "http://ifconfig.me/ip"
		} else {
			$global:externalIP = "No Internet or Redirection"
		}
	} catch {
		$global:externalIP = "No Internet or Error"
	}
	$ProgressPreference = 'Continue'

	# Find gateway and internal IP
	$route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1
	$global:gateway = $route.NextHop
	$gatewayParts = $global:gateway -split '\.'
	$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

	$global:internalIP = (Get-NetIPAddress | Where-Object {
		$_.AddressFamily -eq 'IPv4' -and
		$_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and
		$_.IPAddress -like "$global:gatewayPrefix*"
	}).IPAddress

	# Get current adapter
	$global:adapter = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
		$_.InterfaceAlias -match 'Ethernet|Wi-Fi' -and
		$_.IPAddress -like "$global:gatewayPrefix*"
	}).InterfaceAlias

	# Get MAC address
	$global:myMac = (Get-NetAdapter -Name $global:adapter).MacAddress -replace '-', ':'

	# Get domain
	$global:domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain

	# Mark empty as unknown
	foreach ($item in 'hostName', 'externalIP', 'internalIP', 'adapter', 'gateway', 'domain') {
		if (-not $global:item) {
			$global:item = 'Unknown'
		}
	}
}

function Update-Progress {
	param ($value, $text)
	$Progress.Value = $value
	$BarText.Text = $text
	Update-uiMain
}

# Send packets across subnet
function Scan-Subnet {
	Update-Progress 0 'Sending Packets'

	# Ping Entire Subnet
	1..254 | ForEach-Object {
		Test-Connection -ComputerName "$gatewayPrefix$_" -Count 1 -AsJob | Out-Null
		Update-Progress ($_ * (100 / 254)) 'Sending Packets'
		Start-Sleep -Milliseconds 5
	}
	Update-Progress 100 'Sending Packets'
}

# Give peers time to respond
function waitForResponses {
	Update-Progress 0 'Listening'

	1..100 | ForEach-Object {
		Update-Progress $_ 'Listening'
		Start-Sleep -Milliseconds 140
	}
	Update-Progress 100 'Listening'
}

# Create peer list
function List-Machines {
	Update-Progress 0 'Identifying Devices'

	if($arpInit){
		$arpInit.Clear()
		$arpConverted.Clear()
		$arpOutput.Clear()
	}
	# Filter for Reachable or Stale states and select only IP and MAC address
	$arpInit = Get-NetNeighbor | Where-Object {($_.State -eq "Reachable" -or $_.State -eq "Stale") -and ($_.IPAddress -like "$gatewayPrefix*") -and -not $_.IPAddress.Contains(':')} | Select-Object -Property IPAddress, LinkLayerAddress

	# Convert IP Addresses from string to int by each section
	$arpConverted = $arpInit | Sort-Object -Property {$ip = $_.IPaddress; $ip -split '\.' | ForEach-Object {[int]$_}}

	# Sort by IP using [version] sorting
	$arpOutput = $arpConverted | Sort-Object {[version]$_.IPaddress}
	$self = 0
	$myLastOctet = [int]($internalIP -split '\.')[-1]

	# Get My Vendor via Mac lookup
	$ProgressPreference = 'SilentlyContinue'
	$tryMyVendor = (irm "https://www.macvendorlookup.com/api/v2/$($myMac.Replace(':','').Substring(0,6))" -Method Get).Company
	$ProgressPreference = 'Continue'
	$myVendor = if($tryMyVendor){$tryMyVendor.substring(0, [System.Math]::Min(35, $tryMyVendor.Length))} else {'Unable to Identify'}

	# Cycle through ARP table to populate initial ListView data and start async lookups
	$totalItems = ($arpOutput.Count - 1)

	$hostnameTasks = @{}
	$vendorTasks = @{}

	foreach ($line in $arpOutput) {
		$ip = $line.IPAddress
		$mac = $line.LinkLayerAddress.Replace('-',':')
		$name = if ($ip -eq $internalIP) {"$hostName (This Device)"} else {"Resolving..."}
		$vendor = if ($ip -eq $internalIP) {$myVendor} else {"Identifying..."}

		# Format and display
		$lastOctet = [int]($ip -split '\.')[-1]
		if ($myLastOctet -gt $lastOctet) {
				# Add item with initial placeholder for hostname and vendor
				$item = [pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}
				$listView.Items.Add($item)
		} else {
			if ($self -ge 1) {
				$item = [pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}
				$listView.Items.Add($item)
			} else {
				$listView.Items.Add([pscustomobject]@{'MACaddress'="$myMac";'Vendor'="$myVendor";'IPaddress'="$internalIP";'HostName'="$hostName (This Device)"})
				$item = [pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}
				$listView.Items.Add($item)
				$self++
			}
		}
	}
	$listView.Items.Refresh()
	if ($totalItems -ge 19) {
		$hostNameColumn.Width = 300
	}
	Update-uiMain
}

# Initialize RunspacePool
$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount, $SessionState, $Host)
$RunspacePool.Open()

# Background Vendor lookup
function processVendors {
	$vendorLookupThread = [powershell]::Create().AddScript({
		param ($Main, $listView, $Progress, $BarText, $Scan, $hostName, $gateway, $gatewayPrefix, $internalIP, $myMac)

		function Update-uiBackground{
			param($action)
			$Main.Dispatcher.Invoke([action]$action, [Windows.Threading.DispatcherPriority]::Background)
		}

		function Get-MacVendor($mac) {
			# Get Vendor via Mac (thanks to u/mprz)
			try {
				$ProgressPreference = 'SilentlyContinue'
				$response = (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get)
				$ProgressPreference = 'Continue'
				return $response
			} catch {
				return $null
			}
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
							Update-uiBackground{
								foreach ($it in $listView.Items) {
									if ($it.IPaddress -eq $ipCheck) {
										$it.Vendor = $vendorResult
										$listView.Items.Refresh()
									}
								}

							}
							$vendorTasks.Remove($ipCheck)
						}
					}
					Start-Sleep -Milliseconds 50
				} while ($vendorTasks.Count -ge 7)
			}
		}

		# Temp bugfix for unidentified runaway, last listitem background job always closes before returning a value
		$lastItem = $listView.Items | Select-Object -Last 1
		$lastIP = $lastItem.IPaddress
		$lastMAC = $lastItem.MACaddress
		# Check Vendor
		if ($lastItem.Vendor -eq 'Identifying...' -or $lastItem.Vendor -eq 'Unable to Identify') {
			# Manual vendor lookup for the last IP only if needed
			$lastVendor = Get-MacVendor $lastMAC
			$lastVendorResult = if ($lastVendor -and $lastVendor.Company) {
				$lastVendor.Company.substring(0, [System.Math]::Min(35, $lastVendor.Company.Length))
			} else {
				'Unable to Identify'
			}
			Update-uiBackground{
				$lastItem.Vendor = $lastVendorResult
			}
		}

		# Refresh the ListView if any updates were made
		Update-uiBackground{
			$listView.Items.Refresh()
		}

		# Update any leftover orphans
		Update-uiBackground{
			foreach ($item in $listView.Items) {
				if ($item.Vendor -eq 'Identifying...') {
					$item.Vendor = 'Unable to Identify'
				}
				if ($item.HostName -eq 'Resolving...') {
					$item.HostName = 'Unable to Resolve'
				}
			}
			$listView.Items.Refresh()
		}

		# Clean up jobs
		Remove-Job -Job $vendorTasks.Values -Force

	}, $true).AddArgument($Main).AddArgument($listView).AddArgument($Progress).AddArgument($BarText).AddArgument($Scan).AddArgument($hostName).AddArgument($gateway).AddArgument($gatewayPrefix).AddArgument($internalIP).AddArgument($myMac)
	$vendorLookupThread.RunspacePool = $RunspacePool
	$vendorScan = $vendorLookupThread.BeginInvoke()
}

# Process Hostnames
function processHostnames {
	$hostnameLookupThread = [powershell]::Create().AddScript({
		param ($Main, $listView, $Progress, $BarText, $Scan, $hostName, $gateway, $gatewayPrefix, $internalIP, $myMac)

		function Update-uiBackground{
			param($action)
			$Main.Dispatcher.Invoke([action]$action, [Windows.Threading.DispatcherPriority]::Background)
		}

		$totalhostnamejobs = $listView.Items.Count
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
							Update-uiBackground{
								foreach ($it in $listView.Items) {
									if ($it.IPaddress -eq $ipCheck) {
										$it.HostName = if ([string]::IsNullOrEmpty($entry.HostName)) {
											"Unable to Resolve"
										} else {
											$entry.HostName
										}
										$listView.Items.Refresh()
									}
								}
							}
							$hostnameTasks.Remove($ipCheck)
						}
					}
					Start-Sleep -Milliseconds 50
				} while ($hostnameTasks.Count -ge 7)
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
			}
		}

		# Refresh the ListView if any updates were made
		Update-uiBackground{
			$listView.Items.Refresh()
		}

		# Update any leftover orphans
		Update-uiBackground{
			foreach ($item in $listView.Items) {
				if ($item.HostName -eq 'Resolving...') {
					$item.HostName = 'Unable to Resolve'
				}
			}
			$listView.Items.Refresh()
		}

		# Clean up jobs
		Remove-Job -Job $hostnameTasks.Values -Force

	}, $true).AddArgument($Main).AddArgument($listView).AddArgument($Progress).AddArgument($BarText).AddArgument($Scan).AddArgument($hostName).AddArgument($gateway).AddArgument($gatewayPrefix).AddArgument($internalIP).AddArgument($myMac)
	$hostnameLookupThread.RunspacePool = $RunspacePool
	$hostnameScan = $hostnameLookupThread.BeginInvoke()
}

# Portscan
function CheckConnectivity {
	param (
		[string]$selectedhost
	)
	if ($selectedhost -match ' (This Device)') {
		# Disable all buttons for 'This Device'
		@('btnRDP', 'btnWebInterface', 'btnShare') | ForEach-Object {
			Get-Variable $_ -ValueOnly | ForEach-Object {
				$_.IsEnabled = $false
				$_.Visibility = 'Collapsed'
			}
		}
		$noConnectionsLabel.Text = 'This Device'
		$noConnectionsLabel.Visibility = 'Visible'
		return
	}
	$global:tryToConnect = $selectedhost -replace ' (This Device)', ''
	$noConnectionsLabel.Text = 'No Connections Found'

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

	# Show 'No Connections Found' if no services are available
	$noConnectionsLabel.Visibility = if (-not $btnRDP.IsEnabled -and -not $btnWebInterface.IsEnabled -and -not $btnShare.IsEnabled) { 'Visible' } else { 'Collapsed' }
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
		Height="500" Width="900" Background="#222222" WindowStartupLocation="CenterScreen" ResizeMode="CanMinimize">
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
		<Style x:Key="ListViewStyle" TargetType="{x:Type ListViewItem}" >
			<Setter Property="Background" Value="#111111"/>
			<Setter Property="Foreground" Value="{DynamicResource {x:Static SystemColors.ControlTextBrushKey}}"/>
			<Setter Property="FontWeight" Value="Normal"/>
			<Setter Property="BorderThickness" Value="1"/>
			<Style.Triggers>
				<Trigger Property="ItemsControl.AlternationIndex" Value="0">
					<Setter Property="Background" Value="#111111"/>
					<Setter Property="Foreground" Value="#EEEEEE"/>
				</Trigger>
				<Trigger Property="ItemsControl.AlternationIndex" Value="1">
					<Setter Property="Background" Value="#000000"/>
					<Setter Property="Foreground" Value="#EEEEEE"/>
				</Trigger>
				<Trigger Property="IsMouseOver" Value="True">
					<Setter Property="Background" Value="Transparent" />
					<Setter Property="BorderBrush" Value="#FF00BFFF" />
				</Trigger>
				<MultiTrigger>
					<MultiTrigger.Conditions>
						<Condition Property="IsSelected" Value="true" />
						<Condition Property="Selector.IsSelectionActive" Value="true" />
					</MultiTrigger.Conditions>
					<Setter Property="Background" Value="{DynamicResource {x:Static SystemColors.ControlTextBrushKey}}" />
					<Setter Property="Foreground" Value="#FFFFFF" />
					<Setter Property="FontWeight" Value="Bold"/>
				</MultiTrigger>
			</Style.Triggers>
		</Style>
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
			<Style.Triggers>
				<Trigger Property="IsMouseOver" Value="True">
					<Setter Property="Background" Value="#EEEEEE" />
					<Setter Property="Foreground" Value="Black" />
					<Setter Property="BorderBrush" Value="#333333" />
				</Trigger>
			</Style.Triggers>
		</Style>
	</Window.Resources>
	<Grid Margin="0,0,50,0">
		<Grid Name="ScanContainer" Grid.Column="0" VerticalAlignment="Top" HorizontalAlignment="Center" Width="777" MinHeight="25" Margin="53,9,0,0">
			<Button Name="Scan" Width="777" Height="30" Background="#777777" Foreground="#000000" FontWeight="Bold" Template="{StaticResource NoMouseOverButtonTemplate}">
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
		<ListView Name="listView" Background="#333333" FontWeight="Bold" HorizontalAlignment="Left" Height="400" Margin="12,49,-140,0" VerticalAlignment="Top" Width="860" VerticalContentAlignment="Top" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Hidden" ScrollViewer.CanContentScroll="False" AlternationCount="2" ItemContainerStyle="{StaticResource ListViewStyle}">
			<ListView.View>
				<GridView>
					<GridViewColumn Header="MAC Address" DisplayMemberBinding="{Binding MACaddress}" Width="150" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
					<GridViewColumn Header="Vendor" DisplayMemberBinding="{Binding Vendor}" Width="250" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
					<GridViewColumn Header="IP Address" DisplayMemberBinding="{Binding IPaddress}" Width="140" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
					<GridViewColumn Header="Host Name" DisplayMemberBinding="{Binding HostName}" Width="314" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
				</GridView>
			</ListView.View>
			<ListView.ContextMenu>
				<ContextMenu>
					<MenuItem Header="Export">
						<MenuItem Header="HTML" Name="ExportToHTML"/>
						<MenuItem Header="CSV" Name="ExportToCSV"/>
						<MenuItem Header="Text" Name="ExportToText"/>
					</MenuItem>
				</ContextMenu>
			</ListView.ContextMenu>
		</ListView>
		<Canvas Name="PopupCanvas" Background="#222222" Visibility="Hidden" Width="350" Height="240" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="53,40,0,0">
			<Border Width="350" Height="240" BorderThickness="0.70" BorderBrush="#FF00BFFF">
				<Grid Background="Transparent">
					<Grid.RowDefinitions>
						<RowDefinition Height="Auto"/>
						<RowDefinition Height="*"/>
					</Grid.RowDefinitions>
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
							<TextBlock Name="noConnectionsLabel" Text="No Connections Found" Foreground="#EEEEEE" FontSize="12" Visibility="Collapsed" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,8,0,0"/>
						</StackPanel>
					</StackPanel>
					<Button Name="pCloseButton" Background="#111111" Foreground="#EEEEEE" BorderThickness="0" Content="X" Margin="300,10,0,0" Height="18" Width="22" Template="{StaticResource NoMouseOverButtonTemplate}" Panel.ZIndex="1"/>
				</Grid>
			</Border>
		</Canvas>
	</Grid>
	<Window.Triggers>
		<EventTrigger RoutedEvent="Window.Loaded">
			<BeginStoryboard>
				<Storyboard>
					<ColorAnimationUsingKeyFrames Storyboard.TargetName="CycleBrush" Storyboard.TargetProperty="Color" RepeatBehavior="Forever" Duration="0:0:6">
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
catch{$shell = New-Object -ComObject Wscript.Shell; $shell.Popup("Unable to load GUI, XAML Error!",0,'ERROR:',0x0) | Out-Null; Exit}

# Store Form Objects In PowerShell
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "$($_.Name)" -Value $Main.FindName($_.Name)}

# Set Title and Add Closing
$Main.Title = "$AppId"
$Main.Add_ContentRendered({
	$Main.Activate()
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

$Main.Add_Closing({
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

# Define icons
$icons = @(
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 18; ElementName = "WindowIcon"; Type = "Window"},
	@{File = 'C:\Windows\System32\imageres.dll'; Index = 73; ElementName = "scanAdminIcon"; Type = "Image"},
	@{File = 'C:\Windows\System32\mstscax.dll'; Index = 0; ElementName = "btnRDP"; Type = "Button"},
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 13; ElementName = "btnWebInterface"; Type = "Button"},
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 266; ElementName = "btnShare"; Type = "Button"}
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
			}
			"Image" {
				$element.Source = $bitmapSource
				$element.SetValue([System.Windows.Media.RenderOptions]::BitmapScalingModeProperty, [System.Windows.Media.BitmapScalingMode]::HighQuality)
			}
			"Button" {
				$image = New-Object System.Windows.Controls.Image -Property @{
					Source = $bitmapSource;
					Width = 24;
					Height = 24
				}
				$image.SetValue([System.Windows.Media.RenderOptions]::BitmapScalingModeProperty, [System.Windows.Media.BitmapScalingMode]::HighQuality)
				$element.Content = $image
			}
		}
	}
}

$btnRDP.Add_Click({
	$PopupCanvas.Visibility = 'Hidden'
	&mstsc /v:$tryToConnect
})

$btnRDP.Add_MouseEnter({
	$btnRDP.FindResource("mouseEnterAnimation").Begin($btnRDP)
})

$btnRDP.Add_MouseLeave({
	$btnRDP.FindResource("mouseLeaveAnimation").Begin($btnRDP)
})

$btnWebInterface.Add_Click({
	$btnWebInterface.BorderThickness = "0"
	$PopupCanvas.Visibility = 'Hidden'

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
	$PopupCanvas.Visibility = 'Hidden'
	&explorer "`"\\$tryToConnect`""
})

$btnShare.Add_MouseEnter({
	$btnShare.FindResource("mouseEnterAnimation").Begin($btnShare)
})

$btnShare.Add_MouseLeave({
	$btnShare.FindResource("mouseLeaveAnimation").Begin($btnShare)
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
			$shell = New-Object -ComObject Wscript.Shell
			$shell.Popup("Export to HTML completed successfully!",0,'Export:',0x0) | Out-Null
		}
		catch {
			$shell = New-Object -ComObject Wscript.Shell
			$shell.Popup("Error during export: $_",0,'Error:',0x0) | Out-Null
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
			$shell = New-Object -ComObject Wscript.Shell
			$shell.Popup("Export to CSV completed successfully!",0,'Export:',0x0) | Out-Null
		}
		catch {
			$shell = New-Object -ComObject Wscript.Shell
			$shell.Popup("Error during export: $_",0,'Error:',0x0) | Out-Null
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
			$textContent = @"
NETWORK SCAN RESULTS

EXTERNAL IP: $global:externalIP
DOMAIN     : $global:domain
DATE/TIME  : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

--------------------------------------
"@
			$textContent += $listView.Items | ForEach-Object {
@"

MAC     : $($_.MACaddress)
Vendor  : $($_.Vendor)
IP      : $($_.IPaddress)
Hostname: $($_.HostName.Replace(' (This Device)',''))
--------------------------------------
"@
			}
			[System.IO.File]::WriteAllText($path, $textContent)
			$shell = New-Object -ComObject Wscript.Shell
			$shell.Popup("Export to Text completed successfully!",0,'Export:',0x0) | Out-Null
		}
		catch {
			$shell = New-Object -ComObject Wscript.Shell
			$shell.Popup("Error during export: $_",0,'Error:',0x0) | Out-Null
		}
	}
})

# Add listView column header click capture
$ListView.AddHandler(
	[System.Windows.Controls.GridViewColumnHeader]::ClickEvent,
	[System.Windows.RoutedEventHandler]$listViewSortColumn
)

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
	$PopupCanvas.Visibility = 'Hidden'
	$listView.SelectedItems.Clear()
})

# Clear CTRL key value
$global:CtrlIsDown = $false

# KeyDown event handler
$Main.Add_KeyDown({
	if ($_.Key -eq 'LeftCtrl' -or $_.Key -eq 'RightCtrl') {
		$global:CtrlIsDown = $true
		if($Scan.IsEnabled){
			$scanButtonText.Text = 'Clear Cached Peer List'
			$scanAdminIcon.Visibility = 'Visible'
		}
	}
})

# KeyUp event handler
$Main.Add_KeyUp({
	if ($_.Key -eq 'LeftCtrl' -or $_.Key -eq 'RightCtrl') {
		$global:CtrlIsDown = $false
		if($Scan.IsEnabled){
			$scanButtonText.Text = 'Scan'
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

# Define Scan Button Actions
$Scan.Add_MouseEnter({
	$Scan.Background = '#EEEEEE'
})

$Scan.Add_MouseLeave({
	$Scan.Background = '#777777'
})

$Scan.Add_Click({
	# If CTRL key is held while clicking the Scan button, offer to clear ARP cache as Admin prior to Scan process
	if ($global:CtrlIsDown) {
		$Scan.IsEnabled = $false
		$osInfo = Get-CimInstance Win32_OperatingSystem
		if ($osInfo.Caption -match "Server") {
			$restricted=New-Object -ComObject Wscript.Shell;$restricted.Popup("This option is not available for Windows Servers.`n`nPlease clear your ARP Cache manually.",0,'[Restricted Feature]',0 + 4096) | Out-Null
		} else {
			try{
				Start-Process -Verb RunAs powershell -WindowStyle Minimized -ArgumentList '-Command "& {Remove-NetNeighbor -InterfaceAlias * -Confirm:$false}"'
				$listView.Items.Clear()
				$isCleared=New-Object -ComObject Wscript.Shell;$isCleared.Popup("Cached peer list cleared...",0,'[List Cleared]',0 + 4096) | Out-Null
			}catch{
				$dontClear=New-Object -ComObject Wscript.Shell;$dontClear.Popup("No action was taken...",0,'[Process Aborted]',0 + 4096) | Out-Null
			}
		}
		$scanButtonText.Text = 'Scan'
		$scanAdminIcon.Visibility = 'Collapsed'
		$Scan.IsEnabled = $true
		$global:CtrlIsDown = $false
	} else {
		$Scan.IsEnabled = $false
		# Make ProgressBar visible, hide Button
		$Scan.Visibility = 'Collapsed'
		$Progress.Visibility = 'Visible'
		$Progress.Value = 0
		$BarText.Text = 'Getting localHost Info'
		$listView.Items.Clear()
		$hostNameColumn.Width = 314
		Update-uiMain
		Get-HostInfo
		$Main.Title="$AppId `- `[ External IP: $externalIP `] `- `[ Domain: $domain `]"
		Update-uiMain
		Scan-Subnet
		waitForResponses
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
		Update-uiMain
		$global:CtrlIsDown = $false
	}
})

# Show Window
$Main.ShowDialog() | out-null