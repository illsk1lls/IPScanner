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
		Start-Sleep -Milliseconds 15
	}
	Update-Progress 100 'Sending Packets'
}

# Give peers time to respond
function waitForResponses {
	Update-Progress 0 'Listening'

	1..100 | ForEach-Object {
		Update-Progress $_ 'Listening'
		Start-Sleep -Milliseconds 165
	}
	Update-Progress 100 'Listening'
}

# Initialize RunspacePool
$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount, $SessionState, $Host)
$RunspacePool.Open()

# List peers
function scanProcess {
	$backgroundThread = [powershell]::Create().AddScript({
		param ($Main, $listView, $Progress, $BarText, $Scan, $hostName, $gateway, $gatewayPrefix, $internalIP, $myMac, $hostNameColumn)

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

		function List-Machines {
			Update-uiBackground{
				$Progress.Value = "0"
				$BarText.Text = 'Identifying Devices'
			}

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
			$tryMyVendor = (Get-MacVendor "$myMac").Company
			$myVendor = if($tryMyVendor){$tryMyVendor.substring(0, [System.Math]::Min(35, $tryMyVendor.Length))} else {'Unable to Identify'}

			# Cycle through ARP table to populate initial ListView data and start async lookups
			$i = 0
			$totalItems = $arpOutput.Count - 1

			$asyncTasks = @{}
			$vendorTasks = @{}

			foreach ($line in $arpOutput) {
				$ip = $line.IPAddress
				$mac = $line.LinkLayerAddress.Replace('-',':')
				$name = if ($ip -eq $internalIP) {"$hostName (This Device)"} else {"Resolving..."}
				$vendor = if ($ip -eq $internalIP) {$myVendor} else {"Identifying..."}

				# Format and display
				$lastOctet = [int]($ip -split '\.')[-1]
				if ($myLastOctet -gt $lastOctet) {
					Update-uiBackground{
						# Add item with initial placeholder for hostname and vendor
						$item = [pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}
						$listView.Items.Add($item)
						$Progress.Value = ($i * (100 / $totalItems))
					}
				} else {
					if ($self -ge 1) {
						Update-uiBackground{
							$item = [pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}
							$listView.Items.Add($item)
							$Progress.Value = ($i * (100 / $totalItems))
						}
					} else {
						Update-uiBackground{
							$listView.Items.Add([pscustomobject]@{'MACaddress'="$myMac";'Vendor'="$myVendor";'IPaddress'="$internalIP";'HostName'="$hostName (This Device)"})
							$item = [pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}
							$listView.Items.Add($item)
							$Progress.Value = ($i * (100 / $totalItems))
						}
						$self++
					}
				}

				# Start asynchronous lookups for hostname and vendor immediately after adding item
				if ($ip -ne $internalIP) {
					$hostTask = [System.Net.Dns]::GetHostEntryAsync($ip)
					$vendorTask = Start-Job -ScriptBlock {
						param($mac)
						$ProgressPreference = 'SilentlyContinue'
						$response = (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get)
						$ProgressPreference = 'SilentlyContinue'
						if([string]::IsNullOrEmpty($response.Company)){
							return $null
						} else {
							$response
						}
					} -ArgumentList $mac
					$asyncTasks[$ip] = [PSCustomObject]@{Task = $hostTask; IP = $ip}
					$vendorTasks[$ip] = $vendorTask

					do {
						# Process vendor tasks
						foreach ($ipCheck in @($vendorTasks.Keys)) {
							$vendorTask = $vendorTasks[$ipCheck]
							if ($vendorTask.State -eq "Completed") {
								$result = Receive-Job -Job $vendorTask
								$vendorResult = if ($result -and $result.Company) {
									$result.Company.substring(0, [System.Math]::Min(35, $result.Company.Length))
								} else {
									'Unable to Identify'
								}
								Update-uiBackground{
									foreach ($item in $listView.Items) {
										if ($item.IPaddress -eq $ipCheck) {
											$item.Vendor = $vendorResult
											$listView.Items.Refresh()
										}
									}
								}
								$vendorTasks.Remove($ipCheck)
							}
						}

						# Process hostname tasks
						foreach ($ipCheck in @($asyncTasks.Keys)) {
							$taskObj = $asyncTasks[$ipCheck]
							if ($taskObj.Task.IsCompleted) {
								$entry = $taskObj.Task.Result
								Update-uiBackground{
									foreach ($item in $listView.Items) {
										if ($item.IPaddress -eq $ipCheck) {
											if ([string]::IsNullOrEmpty($entry.HostName)) {
												$item.HostName = "Unable to Resolve"
											} else {
												$item.HostName = $entry.HostName
											}
											$listView.Items.Refresh()
										}
									}
								}
								$asyncTasks.Remove($ipCheck)
							}
						}
						Start-Sleep -Milliseconds 50
					} while ($asyncTasks.Count -ge 8 -or $vendorTasks.Count -ge 8)
				}
				$i++
				if ($i -eq 19) {
					Update-uiBackground{
						$hostNameColumn.Width = 300
					}
				}
			}
		}

		List-Machines

		# Temp bugfix for unidentified runaway, last listitem background job(s) always closes before returning a value(s)
		$lastItem = $listView.Items | Select-Object -Last 1
		$lastIP = $lastItem.IPaddress
		$lastMAC = $lastItem.MACaddress
		# Check Vendor
		if ($lastItem.Vendor -eq "Identifying...") {
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
		# Check HostName
		if ($lastItem.HostName -eq "Resolving...") {
			# Manual hostname lookup for the last IP only if needed
			try {
				$dnsEntry = [System.Net.Dns]::GetHostEntryAsync($lastIP).Result
				$lastHostName = if ($dnsEntry.HostName) { $dnsEntry.HostName } else { "Unable to Resolve" }
			} catch {
				$lastHostName = "Unable to Resolve"
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
				if ($item.Vendor -eq "Identifying...") {
					$item.Vendor = "Unable to Identify"
				}
				if ($item.HostName -eq "Resolving...") {
					$item.HostName = "Unable to Resolve"
				}
			}
			$listView.Items.Refresh()
		}

		# Clean up jobs
		Remove-Job -Job $asyncTasks.Values -Force
		Remove-Job -Job $vendorTasks.Values -Force

		# Final update after all jobs are completed
		Update-uiBackground{
			# Hide ProgressBar, show Button after scan completes
			$Progress.Visibility = 'Collapsed'
			$Scan.Visibility = 'Visible'
			$BarText.Text = ''
			$Scan.IsEnabled = $true
			$Progress.Value = 0
		}
	}, $true).AddArgument($Main).AddArgument($listView).AddArgument($Progress).AddArgument($BarText).AddArgument($Scan).AddArgument($hostName).AddArgument($gateway).AddArgument($gatewayPrefix).AddArgument($internalIP).AddArgument($myMac).AddArgument($hostNameColumn)
	$backgroundThread.RunspacePool = $RunspacePool
	$startScan = $backgroundThread.BeginInvoke()
}

# test connection availability
function CheckConnectivity {
	param (
		[string]$selectedhost
	)
	if ($selectedhost -match ' \(This Device\)') {
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
	$global:tryToConnect = $selectedhost -replace ' \(This Device\)'
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
			$sortDirections[$SortPropertyName] = $false	 # false for descending, true for ascending
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
Add-Type -TypeDefinition $getIcons -ReferencedAssemblies System.Drawing, PresentationCore, PresentationFramework, WindowsBase
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
		</ListView>
		<Canvas Name="PopupCanvas" Background="#222222" Visibility="Hidden" Width="350" Height="240" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="53,-20,0,0">
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
							<Button Name="btnRDP" Width="40" Height="32" ToolTip="Connect via RDP" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="False" Background="Transparent" Margin="0,0,25,0" Template="{StaticResource NoMouseOverButtonTemplate}"/>
							<Button Name="btnWebInterface" Width="40" Height="32" ToolTip="Connect via Web Interface" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="False" Background="Transparent" Margin="0,0,25,0" Template="{StaticResource NoMouseOverButtonTemplate}"/>
							<Button Name="btnShare" Width="40" Height="32" ToolTip="Connect via Share" BorderThickness="0" BorderBrush="#FF00BFFF" IsEnabled="False" Background="Transparent" Template="{StaticResource NoMouseOverButtonTemplate}"/>
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
	$btnRDP.BorderThickness = "0"
	$PopupCanvas.Visibility = 'Hidden'
	&mstsc /v:$tryToConnect
})

$btnRDP.Add_MouseEnter({
	$btnRDP.BorderThickness = ".75"
})

$btnRDP.Add_MouseLeave({
	$btnRDP.BorderThickness = "0"
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
	$btnWebInterface.BorderThickness = ".75"
})

$btnWebInterface.Add_MouseLeave({
	$btnWebInterface.BorderThickness = "0"
})

$btnShare.Add_Click({
	$btnShare.BorderThickness = "0"
	$PopupCanvas.Visibility = 'Hidden'
	&explorer "`"\\$tryToConnect`""
})

$btnShare.Add_MouseEnter({
	$btnShare.BorderThickness = ".75"
})

$btnShare.Add_MouseLeave({
	$btnShare.BorderThickness = "0"
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
		scanProcess
		Update-uiMain
		$global:CtrlIsDown = $false
	}
})

# Show Window
$Main.ShowDialog() | out-null
cmd /pause