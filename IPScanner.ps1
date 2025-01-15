# Hide Console - Show GUI Only
Add-Type -MemberDefinition '[DllImport("User32.dll")]public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -Namespace Win32 -Name Functions
$closeConsoleUseGUI=[Win32.Functions]::ShowWindow((Get-Process -Id $PID).MainWindowHandle,0)

# Check if relaunching to correct terminal type
$reLaunchInProgress=$args[0]

### ADMIN REQUEST SECTION - START ### This is a merge of two functions that both require relaunch. 1) Admin request 2) Adjusting console type momentarily to ensure the console can be hidden
if($reLaunchInProgress -ne 'TerminalSet'){
	# This section is required to hide the console window on Win 11
	if((Get-WmiObject -Class Win32_OperatingSystem).Caption -match "Windows 11") {
		# Define console types
		$legacy='{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}' # This is the legacy console we all know, and can control
		$letWin='{00000000-0000-0000-0000-000000000000}' # This is the default for Win 11
		$terminal='{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}' # This is the first part of "New Terminal"
		$terminal2='{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}' # This key is also required for "New Terminal"
		
		# On brand new Windows installations, if a console window has never been opened this value doesn't exist. Set to default if not present (Simulate 1st console open)
		if(!(Get-ItemProperty 'HKCU:\Console\%%Startup').PSObject.Properties.Name -contains 'DelegationConsole'){
			Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationConsole' -Value $letWin
			Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationTerminal' -Value $letWin
		}
		
		# Store current console settings
		$currentConsole=Get-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationConsole'
		
		# Check if compatible console is selected
		if($currentConsole.DelegationConsole -ne $legacy) {
			$defaultConsole=$currentConsole.DelegationConsole
			# Switch to compatible console settings
			Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationConsole' -Value $legacy
			Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationTerminal' -Value $legacy
			if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
				# Relaunch with temp console settings WITH Admin request - the only task Admin is required for is line #120 to clear ARP cache
				CMD /c START /MIN /HIGH "" POWERSHELL -nop -file "$PSCommandPath" TerminalSet
			} else {
				# Relaunch with temp console settings WITHOUT Admin request
				CMD /c START /MIN "" POWERSHELL -nop -file "$PSCommandPath" TerminalSet
			}
			# Switch back console settings to original state and exit console window that was using those settings
			if($defaultConsole -eq $terminal) {
				Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationConsole' -Value $terminal
				Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationTerminal' -Value $terminal2
			} else {
				Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationConsole' -Value $defaultConsole
				Set-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationTerminal' -Value $defaultConsole
			}
			exit
		}
	}
}
### ADMIN REQUEST SECTION - END ###

# Allow Single Instance Only
$AppId = 'Simple IP Scanner'
$singleInstance = $false
$script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true,([Threading.EventResetMode]::ManualReset),"Global\$AppId",([ref] $singleInstance)
if (-not $singleInstance){
	$shell = New-Object -ComObject Wscript.Shell
	$shell.Popup("$AppId is already running!",0,'ERROR:',0x0) | Out-Null
	Exit
}

# Host info used to determine correct subnet to scan via Gateway prefix
function Get-HostInfo {
	# Hostname
	$global:hostName = hostName

	# Check Internet Connection and Get External IP
	$ProgressPreference = 'SilentlyContinue'
	$hotspotRedirectionTest = irm "http://www.msftncsi.com/ncsi.txt"
	$global:externalIP = if ($hotspotRedirectionTest -eq "Microsoft NCSI") { 
		irm "http://ifconfig.me/ip"
	} else { 
		"No Internet or Redirection"
	}
	$ProgressPreference = 'Continue'
	
	# Find Gateway
	$global:gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).NextHop
	$gatewayParts = $gateway -split '\.'
	$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

	# Internal IP
	$global:internalIP = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and ($_.IPAddress -like "$gatewayPrefix*")}).IPAddress

	# Host adapter type
	$global:adapter = (Get-NetIPAddress -InterfaceAlias "*Ethernet*","*Wi-Fi*" -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "$gatewayPrefix*" }).InterfaceAlias

	# My Mac
	$global:myMac = (Get-NetAdapter -Name $adapter).MacAddress.Replace('-',':')

	# Convert subnet prefix to readable number
	$prefixLength = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1'} | Select-Object -First 1).PrefixLength
	$subnetMask = ([System.Net.IPAddress]::Parse(($([Math]::Pow(2, $prefixLength)) - 1) * [Math]::Pow(2, 32 - $prefixLength))).GetAddressBytes() -join "."

	# Domain
	$global:domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain

	# Mark empty as Unknown
	$markUnknown = @('hostName', 'externalIP', 'internalIP', 'adapter', 'subnetMask', 'gateway', 'domain')
	foreach ($item in $markUnknown) {
		if (-not (Get-Variable -Name $item -ValueOnly -ErrorAction SilentlyContinue)) {
			Set-Variable -Name $item -Value 'Unknown' -Scope Global
		}
	}
}

function Get-MacVendor($mac) {
	# Get Vendor via Mac (thanks to u/mprz)
	return (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get)
}

# Get ARP table ready and refresh
function Scan-Subnet {
	$Progress.Value = 0
	$BarText.Content = 'Sending Packets'

	# Clear ARP cache - Requires Admin
	Remove-NetNeighbor -InterfaceAlias "$adapter" -AsJob -Confirm:$false | Out-Null

	# Ping Entire Subnet
	for ($i = 1; $i -le 254; $i++) {
		Test-Connection $gatewayPrefix$i -Count 1 -AsJob | Out-Null
		$Progress.Value = ($i * (100 / 254))
		Start-Sleep -Milliseconds 10
		Update-Gui
	}
}

# Give machines time to respond
function waitForResponses {
	$Progress.Value = 0
	$BarText.Content = 'Listening'

	# Wait with progress
	for ($i = 1; $i -le 100; $i++) {
		$Progress.Value = $i
		Update-Gui
		Start-Sleep -Milliseconds 150
	}
}

# Build ListView
function List-Machines {
	$Progress.Value = "0"
	$BarText.Content = 'Resolving Remote Hostnames'
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
			$listView.items.Add([pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}) | Out-Null
			Update-Gui
		} else {
			if ($self -ge 1) {
				$listView.items.Add([pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}) | Out-Null
				Update-Gui
			} else {
				$listView.items.Add([pscustomobject]@{'MACaddress'="$myMac";'Vendor'="$myVendor";'IPaddress'="$internalIP";'HostName'="$hostName (This Device)"}) | Out-Null
				Update-Gui
				$listView.items.Add([pscustomobject]@{'MACaddress'="$mac";'Vendor'="$vendor";'IPaddress'="$ip";'HostName'="$name"}) | Out-Null
				Update-Gui
				$self++
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

# No multi-threading in this version ;(
function Update-Gui(){
	$Main.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Background, [action]{})
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
		<Style x:Key="{x:Type ScrollBar}" TargetType="{x:Type ScrollBar}">
			<Setter Property="Stylus.IsFlicksEnabled" Value="True" />
			<Style.Triggers>
				<Trigger Property="Orientation" Value="Vertical">
					<Setter Property="Width" Value="10" />
					<Setter Property="MinWidth" Value="10" />
				</Trigger>
			</Style.Triggers>
		</Style>
	</Window.Resources>		
	<Grid Margin="0,0,50,0">
		<Button Name="Scan" Background="#000000" Foreground="#000000" Grid.Column="0" VerticalAlignment="Top" HorizontalAlignment="Center" Width="777" MinHeight="25" Margin="53,9,0,0" Template="{StaticResource NoMouseOverButtonTemplate}">
			<Grid>
				<ProgressBar Name="Progress" Background="#777777" Value="0" Maximum="100" Width="775" Height="30" VerticalAlignment="Stretch" HorizontalAlignment="Stretch"/>
				<Label Name="BarText" Foreground="#000000" FontWeight="Bold" Content="Scan" Width="250" Height="30" VerticalAlignment="Stretch" HorizontalAlignment="Stretch" VerticalContentAlignment="Center" HorizontalContentAlignment="Center"/>
			</Grid>
		</Button>
	   <ListView Name="listView" Background="#333333" FontWeight="Bold" HorizontalAlignment="Left" Height="400" Margin="12,49,-140,0" VerticalAlignment="Top" Width="860" VerticalContentAlignment="Top" ScrollViewer.VerticalScrollBarVisibility="Visible" ScrollViewer.CanContentScroll="False" AlternationCount="2" ItemContainerStyle="{StaticResource ListViewStyle}">
			<ListView.View>
				<GridView>
					<GridViewColumn Header= "MAC Address" DisplayMemberBinding ="{Binding MACaddress}" Width="150"/>
					<GridViewColumn Header= "Vendor" DisplayMemberBinding ="{Binding Vendor}" Width="250"/>
					<GridViewColumn Header= "IP Address" DisplayMemberBinding ="{Binding IPaddress}" Width="140"/>
					<GridViewColumn Header= "Host Name" DisplayMemberBinding ="{Binding HostName}" Width="300"/>
				</GridView>
			</ListView.View>
		</ListView>
	</Grid>
</Window>
'@

# Load XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml) 
try{$Main = [Windows.Markup.XamlReader]::Load( $reader )}
catch{$shell = New-Object -ComObject Wscript.Shell; $shell.Popup("Unable to load GUI!",0,'ERROR:',0x0) | Out-Null; Exit}

# Store Form Objects In PowerShell
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "$($_.Name)" -Value $Main.FindName($_.Name)}

# Set Title and Add Closing
$Main.Title = "$AppId"
$Main.Add_Closing({[System.Windows.Forms.Application]::Exit();Stop-Process $pid})

# Actions on ListItem Double-Click
$listView.Add_MouseDoubleClick({
	if($listView.SelectedItems.HostName -ne 'Unable to Resolve'){
		$selectedHost = $listView.SelectedItems.HostName
	} else {
		$selectedHost = $listView.SelectedItems.IPaddress
	}
	Launch-WebInterfaceOrShare -selectedhost "$selectedHost"
})

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
	$BarText.Content = 'Getting localHost Info'
	$Scan.IsEnabled = $false
	if($listview.Items){
		$listview.Items.Clear()
	}
	Update-Gui
	Get-HostInfo
	$Main.Title="$AppId `- `[ External IP: $externalIP `] `- `[ Domain: $domain `]"
	Scan-Subnet
	waitForResponses
	List-Machines
	$BarText.Content = 'Scan'
	$Scan.IsEnabled = $true
})

# Ensure clean ListView before launching
if($listview.Items){
	$listview.Items.Clear()
}

# Show Window
$Main.ShowDialog() | out-null
$appContext=New-Object System.Windows.Forms.ApplicationContext
[void][System.Windows.Forms.Application]::Run($appContext)
