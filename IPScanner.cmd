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

# Get host machine information
function Get-HostInfo {
	# Get Hostname
	$global:hostName = hostname

	# Check internet connection and get external IP
	$ProgressPreference = 'SilentlyContinue'
	$hotspotRedirectionTest = irm "http://www.msftncsi.com/ncsi.txt"
	$global:externalIP = if ($hotspotRedirectionTest -eq "Microsoft NCSI") {
		irm "http://ifconfig.me/ip"
	} else {
		"No Internet or Redirection"
	}
	$ProgressPreference = 'Continue'

	# Find my gateway
	$global:gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).NextHop
	$gatewayParts = $gateway -split '\.'
	$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

	# Get my Internal IP
	$global:internalIP = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and ($_.IPAddress -like "$gatewayPrefix*")}).IPAddress

	# Get current adapter type
	$global:adapter = (Get-NetIPAddress -InterfaceAlias "*Ethernet*","*Wi-Fi*" -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "$gatewayPrefix*" }).InterfaceAlias

	# Get my mac
	$global:myMac = (Get-NetAdapter -Name $adapter).MacAddress.Replace('-',':')

	# Convert subnet prefix to readable number
	$prefixLength = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1'} | Select-Object -First 1).PrefixLength
	$subnetMask = ([System.Net.IPAddress]::Parse(($([Math]::Pow(2, $prefixLength)) - 1) * [Math]::Pow(2, 32 - $prefixLength))).GetAddressBytes() -join "."

	# Get domain
	$global:domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain

	# Mark empty as unknown
	$hostData = @('hostName', 'externalIP', 'internalIP', 'adapter', 'subnetMask', 'gateway', 'domain')
	foreach ($item in $hostData) {
		if (-not (Get-Variable -Name $item -ValueOnly -ErrorAction SilentlyContinue)) {
			Set-Variable -Name $item -Value 'Unknown' -Scope Global
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
				$response = irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get -TimeoutSec 5
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
			$arpInit = Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" -or $_.State -eq "Stale" } | Select-Object -Property IPAddress, LinkLayerAddress

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
						$response = (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get -TimeoutSec 5)
						if([string]::IsNullOrEmpty($response.Company)){
							return $null
						} else {
							$response
						}
					} -ArgumentList $mac

					$asyncTasks[$ip] = [PSCustomObject]@{Task = $hostTask; IP = $ip}
					$vendorTasks[$ip] = $vendorTask

					# Immediately check for any completed tasks
					foreach ($ipCheck in @($asyncTasks.Keys)) {
						$taskObj = $asyncTasks[$ipCheck]
						if ($taskObj.Task.IsCompleted) {
							try {
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
							} catch {
								Update-uiBackground{
									foreach ($item in $listView.Items) {
										if ($item.IPaddress -eq $ipCheck) {
											$item.HostName = "Unable to Resolve"
											$listView.Items.Refresh()
										}
									}
								}
								$asyncTasks.Remove($ipCheck)
							}
						}
					}

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
							Remove-Job -Job $vendorTask
							$vendorTasks.Remove($ipCheck)
						}
					}
				}
				$i++
				if ($i -eq 19) {
					Update-uiBackground{
						$hostNameColumn.Width = 300
					}
				}
			}

			# After processing, reset the scan button
			Update-uiBackground{
				# Hide ProgressBar, show Button after scan completes
				$Progress.Visibility = 'Collapsed'
				$Scan.Visibility = 'Visible'
				$BarText.Text = ''
				$Scan.IsEnabled = $true
				$Progress.Value = 0
			}
		}
		List-Machines
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
		$btnRDP.IsEnabled = $false
		$btnRDP.Visibility = 'Collapsed'
		$btnWebInterface.IsEnabled = $false
		$btnWebInterface.Visibility = 'Collapsed'
		$btnShare.IsEnabled = $false
		$btnShare.Visibility = 'Collapsed'
		$noConnectionsLabel.Text = 'This Device'
		$noConnectionsLabel.Visibility = 'Visible'
	} else {
		$global:tryToConnect = $selectedhost.Replace(' (This Device)','')
		$noConnectionsLabel.Text = 'No Connections Found'

		# Check if WebInterface exists HTTP then HTTPS
		$TCPClientHTTP = [System.Net.Sockets.TcpClient]::new()
		$ResultHTTP = $TCPClientHTTP.ConnectAsync($tryToConnect, 80).Wait(250)
		$TCPClientHTTP.Close()
		if(!($ResultHTTP)){
			$TCPClientHTTPS = [System.Net.Sockets.TcpClient]::new()
			$ResultHTTPS = $TCPClientHTTPS.ConnectAsync($tryToConnect, 443).Wait(250)
			$TCPClientHTTPS.Close()
		}

		$TCPClientSMBv2 = [System.Net.Sockets.TcpClient]::new()
		$ResultSMBv2 = $TCPClientSMBv2.ConnectAsync($tryToConnect, 445).Wait(250)
		$TCPClientSMBv2.Close()
		if(!($ResultSMBv2)){
			$TCPClientSMB = [System.Net.Sockets.TcpClient]::new()
			$ResultSMB = $TCPClientSMB.ConnectAsync($tryToConnect, 139).Wait(250)
			$TCPClientSMB.Close()
		}

		$TCPClientRDP = [System.Net.Sockets.TcpClient]::new()
		$ResultRDP = $TCPClientRDP.ConnectAsync($tryToConnect, 3389).Wait(250)
		$TCPClientRDP.Close()

		if($ResultRDP -and $HostName -ne $tryToConnect) {
			$btnRDP.IsEnabled = $true
			$btnRDP.Visibility = 'Visible'
		} else {
			$btnRDP.IsEnabled = $false
			$btnRDP.Visibility = 'Collapsed'
		}

		# Priority order: HTTP/HTTPS
		if($ResultHTTP -and $HostName -ne $tryToConnect) {
			$btnWebInterface.IsEnabled = $true
			$btnWebInterface.Visibility = 'Visible'
			$global:httpAvailable=1
		} elseif($ResultHTTPS -and $HostName -ne $tryToConnect) {
			$btnWebInterface.IsEnabled = $true
			$btnWebInterface.Visibility = 'Visible'
		} else {
			$btnWebInterface.IsEnabled = $false
			$btnWebInterface.Visibility = 'Collapsed'
		}

		# Priority order: SMBv2/SMB
		if($ResultSMBv2 -and $HostName -ne $tryToConnect) {
			$btnShare.IsEnabled = $true
			$btnShare.Visibility = 'Visible'
		} elseif($ResultSMB -and $HostName -ne $tryToConnect) {
			$btnShare.IsEnabled = $true
			$btnShare.Visibility = 'Visible'
		} else {
			$btnShare.IsEnabled = $false
			$btnShare.Visibility = 'Collapsed'
		}
		if (-not $ResultRDP -and -not ($ResultHTTPS -or $ResultHTTP) -and -not ($ResultSMBv2 -or $ResultSMB)) {
			$noConnectionsLabel.Visibility = 'Visible'
		} else {
			$noConnectionsLabel.Visibility = 'Collapsed'
		}
	}
}

# This function is needed to make sure sorting by [version] is maintained when sorting by IP Address
$priorSorting = $false
$listViewSortColumn = {
	param([System.Object]$sender, [System.EventArgs]$Event)

	$SortPropertyName = $Event.OriginalSource.Column.DisplayMemberBinding.Path.Path

	# Check if sorting the IP Address column
	if ($SortPropertyName -eq "IPaddress") {
		# Use version sorting for IP addresses
		$sortDescription = $Sender.Items.SortDescriptions | Where-Object { $_.PropertyName -eq $SortPropertyName }

		Switch ($True)
		{
			{-not $sortDescription}
			{
				# If no sorting has occurred before, start with descending for IPaddress
				$Direction = if($priorSorting) {[System.ComponentModel.ListSortDirection]::Ascending} else {[System.ComponentModel.ListSortDirection]::Descending}
				$priorSorting = $true
			}

			{$sortDescription.Direction -eq [System.ComponentModel.ListSortDirection]::Descending}
			{$Direction = [System.ComponentModel.ListSortDirection]::Ascending}

			{$sortDescription.Direction -eq [System.ComponentModel.ListSortDirection]::Ascending}
			{$Direction = [System.ComponentModel.ListSortDirection]::Descending}

			{$sortDescription}
			{$Sender.Items.SortDescriptions.Remove($sortDescription)}

			{$Direction -is [System.ComponentModel.ListSortDirection]}
			{
				$Sender.Items.SortDescriptions.Insert(0,
					[System.ComponentModel.SortDescription]::new($SortPropertyName, $Direction)
				)

				# Sort the items before re-adding them to the ListView
				$sortedItems = $Sender.Items | Sort-Object -Property @{Expression={[version]$_.IPaddress}; Ascending=($Direction -eq [System.ComponentModel.ListSortDirection]::Ascending)}
				$Sender.Items.Clear()
				$sortedItems | ForEach-Object { $Sender.Items.Add($_) }
			}
		}
	} else {
		# Default sorting for other columns
		$sortDescription = $Sender.Items.SortDescriptions | Where-Object { $_.PropertyName -eq $SortPropertyName }

		Switch ($True)
		{
			{-not $sortDescription}
			{
				$Direction = [System.ComponentModel.ListSortDirection]::Ascending
				$priorSorting = $true
			}

			{$sortDescription.Direction -eq [System.ComponentModel.ListSortDirection]::Descending}
			{$Direction = [System.ComponentModel.ListSortDirection]::Ascending}

			{$sortDescription.Direction -eq [System.ComponentModel.ListSortDirection]::Ascending}
			{$Direction = [System.ComponentModel.ListSortDirection]::Descending}

			{$sortDescription}
			{$Sender.Items.SortDescriptions.Remove($sortDescription)}

			{$Direction -is [System.ComponentModel.ListSortDirection]}
			{
				$newSortDescription = [System.ComponentModel.SortDescription]::new($SortPropertyName,$Direction)
				$Sender.Items.SortDescriptions.Insert(0,$newSortDescription)
			}
		}
	}
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
			<Setter Property="Foreground" Value="#EEEEEE"/>
			<Setter Property="FontWeight" Value="Normal"/>
			<Setter Property="BorderThickness" Value="1"/>
			<Style.Triggers>
				<Trigger Property="ItemsControl.AlternationIndex" Value="1">
					<Setter Property="Background" Value="#000000"/>
					<Setter Property="Foreground" Value="#EEEEEE"/>
				</Trigger>
				<Trigger Property="IsMouseOver" Value="True">
					<Setter Property="Background" Value="Transparent" />
					<Setter Property="BorderBrush" Value="#333333" />
				</Trigger>
				<MultiTrigger>
					<MultiTrigger.Conditions>
						<Condition Property="IsSelected" Value="true" />
						<Condition Property="Selector.IsSelectionActive" Value="true" />
					</MultiTrigger.Conditions>
					<Setter Property="Background" Value="{x:Static SystemColors.ControlDarkDarkBrush}" />
					<Setter Property="Foreground" Value="#000000" />
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
		<Canvas Name="PopupCanvas" Background="#111111" Visibility="Hidden" Width="350" Height="140" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="53,10,0,0">
			<Border Width="350" Height="140" BorderThickness="1" BorderBrush="#FF000000">
				<Grid Background="Transparent">
					<Grid.RowDefinitions>
						<RowDefinition Height="Auto"/>
						<RowDefinition Height="*"/>
					</Grid.RowDefinitions>
					<StackPanel Margin="10" Grid.Row="1">
						<TextBlock Name="pHost" Foreground="#EEEEEE" FontWeight="Bold" Margin="10,-15,0,0"/>
						<TextBlock Name="pIP" Foreground="#EEEEEE" Margin="10,0,0,0" />
						<TextBlock Name="pMAC" Foreground="#EEEEEE" Margin="10,0,0,0" />
						<TextBlock Name="pVendor" Foreground="#EEEEEE" Margin="10,0,0,0" />
						<StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,6,0,0">
							<Button Name="btnRDP" Width="40" Height="32" ToolTip="Connect via RDP" BorderThickness="0" BorderBrush="#333333" IsEnabled="False" Background="Transparent" Margin="0,0,15,0" Template="{StaticResource NoMouseOverButtonTemplate}"/>
							<Button Name="btnWebInterface" Width="40" Height="32" ToolTip="Connect via Web Interface" BorderThickness="0" BorderBrush="#333333" IsEnabled="False" Background="Transparent" Margin="0,0,15,0" Template="{StaticResource NoMouseOverButtonTemplate}"/>
							<Button Name="btnShare" Width="40" Height="32" ToolTip="Connect via Share" BorderThickness="0" BorderBrush="#333333" IsEnabled="False" Background="Transparent" Template="{StaticResource NoMouseOverButtonTemplate}"/>
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

# Extract and set icons for buttons
$icons = @(
	@{File = 'C:\Windows\System32\mstscax.dll'; Index = 0; ButtonName = "btnRDP"},
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 13; ButtonName = "btnWebInterface"},
	@{File = 'C:\Windows\System32\shell32.dll'; Index = 266; ButtonName = "btnShare"}
)

foreach ($icon in $icons) {
	$extractedIcon = [System.IconExtractor]::Extract($icon.File, $icon.Index, $true)

	if ($extractedIcon) {
		$bitmapSource = [System.IconExtractor]::IconToBitmapSource($extractedIcon)
		$image = New-Object System.Windows.Controls.Image -Property @{
			Source = $bitmapSource;
			Width = 24;
			Height = 24
		}

		$image.SetValue([System.Windows.Media.RenderOptions]::BitmapScalingModeProperty, [System.Windows.Media.BitmapScalingMode]::HighQuality)

		$button = $Main.FindName($icon.ButtonName)
		$button.Content = $image
	}
}

# This icon is shown on the Scan button if either the Left or Right CTRL key is held
$adminIcon = [System.IconExtractor]::Extract('C:\Windows\System32\imageres.dll', 73, $true)
$scanAdminIcon.Source = [System.IconExtractor]::IconToBitmapSource($adminIcon)
$scanAdminIcon.SetValue([System.Windows.Media.RenderOptions]::BitmapScalingModeProperty, [System.Windows.Media.BitmapScalingMode]::HighQuality)


# Extract and set icon for window and taskbar
$mainIcon = [System.IconExtractor]::Extract('C:\Windows\System32\shell32.dll', 18, $true)
$mainIconBitmap = [System.IconExtractor]::IconToBitmapSource($mainIcon)

# Set Window Icon
$Main.Icon = $mainIconBitmap
# Set Taskbar Icon
$Main.TaskbarItemInfo.Overlay = $mainIconBitmap
$Main.TaskbarItemInfo.Description = $AppId

$btnRDP.Add_Click({
	$btnRDP.BorderThickness = "0"
	$PopupCanvas.Visibility = 'Hidden'
	&mstsc /v:$tryToConnect
})

$btnRDP.Add_MouseEnter({
	$btnRDP.BorderThickness = "1"
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
	$btnWebInterface.BorderThickness = "1"
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
	$btnShare.BorderThickness = "1"
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

# Variable to track if Ctrl is down
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
		$listView.Items.Clear()
		$hostNameColumn.Width = 314
		# Make ProgressBar visible, hide Button
		$Scan.Visibility = 'Collapsed'
		$Progress.Visibility = 'Visible'
		$Progress.Value = 0	 # Reset progress bar
		$BarText.Text = 'Getting localHost Info'
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