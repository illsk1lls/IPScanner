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

	# Mark empty as Unknown
	$markUnknown = @('hostName', 'externalIP', 'internalIP', 'adapter', 'subnetMask', 'gateway', 'domain')
	foreach ($item in $markUnknown) {
		if (-not (Get-Variable -Name $item -ValueOnly -ErrorAction SilentlyContinue)) {
			Set-Variable -Name $item -Value 'Unknown' -Scope Global
		}
	}
}

function Update-Progress {
	param ($value, $text)
	$Progress.Value = $value
	$BarText.Content = $text
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
			return (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get)
		}

		function List-Machines {
			Update-uiBackground{
				$Progress.Value = "0"
				$BarText.Content = 'Resolving Remote Hostnames'
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
			$myVendor = if($tryMyVendor){$tryMyVendor.substring(0, [System.Math]::Min(35, $tryMyVendor.Length))} else {'Unknown'}

			# Cycle through ARP table
			$i = 0
			$totalItems = $arpOutput.Count - 1
			foreach ($line in $arpOutput) {
				$ip = $line.IPAddress
				$mac = $line.LinkLayerAddress.Replace('-',':')
				$name = (Resolve-DnsName -Name $ip -Server $gateway -ErrorAction SilentlyContinue).NameHost

				# Check if $name is null or empty since no DNS record was found
				if (!($name)) {
					$name = "Unable to Resolve"
				}

				# Get Remote Device Vendor via Mac lookup
				$tryVendor=(Get-MacVendor "$mac").Company
				$vendor = if($tryVendor){$tryVendor.substring(0, [System.Math]::Min(35, $tryVendor.Length))} else {'Unknown'}

				# Format and display
				$lastOctet = [int]($ip -split '\.')[-1]
				if ($myLastOctet -gt $lastOctet) {
					Update-uiBackground{
						$listView.Items.Add([pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"})
						$Progress.Value = ($i * (100 / $totalItems))
					}
				} else {
					if ($self -ge 1) {
						Update-uiBackground{
							$listView.Items.Add([pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"})
							$Progress.Value = ($i * (100 / $totalItems))
						}
					} else {
						Update-uiBackground{
							if ($i -eq 0) { $listView.Items.Clear() }  # Clear only once at the start
							$listView.Items.Add([pscustomobject]@{'MACaddress'="$myMac";'Vendor'="$myVendor";'IPaddress'="$internalIP";'HostName'="$hostName (This Device)"})
							$listView.Items.Add([pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"})
							$Progress.Value = ($i * (100 / $totalItems))
						}
						$self++
					}
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
		Update-uiBackground{
			# Reset Scan button
			$BarText.Content = 'Scan'
			$Scan.IsEnabled = $true
			$Progress.Value = 0
		}
	}, $true).AddArgument($Main).AddArgument($listView).AddArgument($Progress).AddArgument($BarText).AddArgument($Scan).AddArgument($hostName).AddArgument($gateway).AddArgument($gatewayPrefix).AddArgument($internalIP).AddArgument($myMac).AddArgument($hostNameColumn)

	$backgroundThread.RunspacePool = $RunspacePool
	$startScan = $backgroundThread.BeginInvoke()
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

# Launch selected item in browser or file explorer
function Launch-WebInterfaceOrShare {
	param (
		[string]$selectedhost
	)
	$launch = $selectedhost.Replace(' (This Device)','')

	# Check if WebInterface exists HTTPS then HTTP
	$TCPClientS = [System.Net.Sockets.TcpClient]::new()
	$ResultS = $TCPClientS.ConnectAsync($launch, 443).Wait(250)
	$TCPClientS.Close()
	if(!($ResultS)){
		$TCPClient = [System.Net.Sockets.TcpClient]::new()
		$Result = $TCPClient.ConnectAsync($launch, 80).Wait(250)
		$TCPClient.Close()
	}

	# Priority order: HTTPS/HTTP/BrowseShare
	if($ResultS -and $HostName -ne $launch) {
		Start-Process "`"https://$launch`""
	} elseif($Result -and $HostName -ne $launch) {
		Start-Process "`"http://$launch`""
	} else {
		&explorer "`"\\$launch`""
	}
}

# Define WPF GUI Structure
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
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
			<Setter Property="BorderThickness" Value="0,0,1,0" />
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
		<Button Name="Scan" Background="#000000" Foreground="#000000" Grid.Column="0" VerticalAlignment="Top" HorizontalAlignment="Center" Width="777" MinHeight="25" Margin="53,9,0,0" Template="{StaticResource NoMouseOverButtonTemplate}">
			<Grid>
				<ProgressBar Name="Progress" Foreground="#FF00BFFF" Background="#777777" Value="0" Maximum="100" Width="775" Height="30" VerticalAlignment="Stretch" HorizontalAlignment="Stretch"/>
				<Label Name="BarText" Foreground="#000000" FontWeight="Bold" Content="Scan" Width="250" Height="30" VerticalAlignment="Stretch" HorizontalAlignment="Stretch" VerticalContentAlignment="Center" HorizontalContentAlignment="Center"/>
			</Grid>
		</Button>
		<ListView Name="listView" Background="#333333" FontWeight="Bold" HorizontalAlignment="Left" Height="400" Margin="12,49,-140,0" VerticalAlignment="Top" Width="860" VerticalContentAlignment="Top" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Hidden" ScrollViewer.CanContentScroll="False" AlternationCount="2" ItemContainerStyle="{StaticResource ListViewStyle}">
			<ListView.View>
				<GridView>
					<GridViewColumn Header= "MAC Address" DisplayMemberBinding ="{Binding MACaddress}" Width="150" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
					<GridViewColumn Header= "Vendor" DisplayMemberBinding ="{Binding Vendor}" Width="250" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
					<GridViewColumn Header= "IP Address" DisplayMemberBinding ="{Binding IPaddress}" Width="140" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
					<GridViewColumn Header= "Host Name" DisplayMemberBinding ="{Binding HostName}" Width="314" HeaderContainerStyle="{StaticResource ColumnHeaderStyle}" />
				</GridView>
			</ListView.View>
		</ListView>
	</Grid>
	<Window.Triggers>
		<EventTrigger RoutedEvent="Loaded">
			<BeginStoryboard>
				<Storyboard Duration="00:00:1" Storyboard.TargetProperty="Opacity">
					<DoubleAnimation From="0" To="1"/>
				</Storyboard>
			</BeginStoryboard>
		</EventTrigger>
	</Window.Triggers>
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

# Add listView column header click capture
$ListView.AddHandler(
	[System.Windows.Controls.GridViewColumnHeader]::ClickEvent,
	[System.Windows.RoutedEventHandler]$listViewSortColumn
)

$hostNameColumn = ($listView.View.Columns | Where-Object {$_.Header -eq "Host Name"})

# Actions on ListItem Double-Click
$listView.Add_MouseDoubleClick({
	if($listView.SelectedItems.IPaddress){
		if($listView.SelectedItems.HostName -ne 'Unable to Resolve'){
			$selectedHost = $listView.SelectedItems.HostName
		} else {
			$selectedHost = $listView.SelectedItems.IPaddress
		}
		Launch-WebInterfaceOrShare -selectedhost "$selectedHost"
	}
})

$listView.Add_MouseLeftButtonDown({
	$listView.SelectedItems.Clear()
})

# Ensure clean ListView
if($listview.Items){
	$listview.Items.Clear()
}

# Define Scan Button Actions
$Scan.Add_MouseEnter({
	$Progress.Background = '#EEEEEE'
	$BarText.Foreground = '#000000'
})

$Scan.Add_MouseLeave({
	$Progress.Background = '#777777'
	$BarText.Foreground = '#000000'
})

$Scan.Add_Click({
	# If CTRL key is held while clicking the Scan button, offer to clear ARP cache as Admin prior to Scan process
	$CtrlKey = '0x11'
	$CheckCtrlHeldDuringScan='[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]public static extern short GetAsyncKeyState(int virtualKeyCode);'
	Add-Type -MemberDefinition $CheckCtrlHeldDuringScan -Name Keyboard -Namespace PsOneApi
	if([bool]([PsOneApi.Keyboard]::GetAsyncKeyState($CtrlKey) -eq -32767)){
		$clearCache=New-Object -ComObject Wscript.Shell;$doClearCache=$clearCache.Popup("Do you want to clear the cached peer list before scanning?",0,'[Admin Required]',1 + 4096)
		if($doClearCache -eq 1){
			Start-Process -Verb RunAs powershell -WindowStyle Minimized -ArgumentList '-Command "& {Remove-NetNeighbor -InterfaceAlias * -Confirm:$false}"'
			$isCleared=New-Object -ComObject Wscript.Shell;$isCleared.Popup("Network Peer list cleared...",0,'[List Cleared]',0 + 4096) | Out-Null
		} else {
			$dontClear=New-Object -ComObject Wscript.Shell;$dontClear.Popup("Continuing Scan in Normal Mode...",0,'[Process Aborted]',0 + 4096) | Out-Null
		}
	}
	$Scan.IsEnabled = $false
	$listView.Items.Clear()
	$hostNameColumn.Width = 314
	$BarText.Content = 'Getting localHost Info'
	Update-uiMain
	Get-HostInfo
	$Main.Title="$AppId `- `[ External IP: $externalIP `] `- `[ Domain: $domain `]"
	Update-uiMain
	Scan-Subnet
	waitForResponses
	scanProcess
	Update-uiMain
})

# Show Window
$Main.ShowDialog() | out-null