# Hide Console - Show GUI Only
Add-Type -MemberDefinition '[DllImport("User32.dll")]public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -Namespace Win32 -Name Functions
$closeConsoleUseGUI=[Win32.Functions]::ShowWindow((Get-Process -Id $PID).MainWindowHandle,0)

# Generate Admin request. Admin required to clear ARP cache for fresh network list - this is the only task it is required for, line #74
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process Powershell "-nop -c `"iex ([io.file]::ReadAllText(`'$PSCommandPath`'))`"" -Verb RunAs
	exit
}

# Allow Single Instance Only
$AppId = 'Primitive IPScanner'
$singleInstance = $false
$script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true,([Threading.EventResetMode]::ManualReset),"Global\$AppId",([ref] $singleInstance)
if (-not $singleInstance){
	$shell = New-Object -ComObject Wscript.Shell
	$shell.Popup("Primitive IPScanner is already running!",0,'ERROR:',0x0) | Out-Null
	Exit
}

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
	$gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).NextHop
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
	$SetFinalVar = @('hostName', 'externalIP', 'internalIP', 'adapter', 'subnetMask', 'gateway', 'domain')
	foreach ($var in $SetFinalVar) {
		Set-Variable -Name $var -Value (Get-Variable -Name $var -ErrorAction SilentlyContinue).Value ?? 'Unknown'
	}

}

function Get-MacVendor($mac) {
	# Get Vendor via Mac (thanks to u/mprz)
	return (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get)
}

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

function List-Machines {
	$Progress.Value = "0"
	$BarText.Content = 'Generating List'

	# Filter for Reachable or Stale states and select only IP and MAC address
	$arpOutput = Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" -or $_.State -eq "Stale" } | Select-Object -Property IPAddress, LinkLayerAddress | Sort-Object -Property IPAddress
	$self = 0
	$myLastOctet = [int]($internalIP -split '\.')[-1]
	
	# Get My Vendor via Mac lookup
	$tryMyVendor = (Get-MacVendor "$myMac").Company
	$myVendor = if($tryMyVendor){$tryMyVendor.substring(0, [System.Math]::Min(25, $tryMyVendor.Length))} else {'Unknown'}

	# Cycle through ARP table
	foreach ($line in $arpOutput) {
		$ip = $line.IPAddress
		$mac = $line.LinkLayerAddress.Replace('-',':')
		$name = try {
			([System.Net.Dns]::GetHostEntry($ip)).HostName
		} catch {
			"Unable to Resolve"
		}
		# Get Remote Device Vendor via Mac lookup
		$tryVendor=(Get-MacVendor "$mac").Company
		$vendor = if($tryVendor){$tryVendor.substring(0, [System.Math]::Min(25, $tryVendor.Length))} else {'Unknown'}		

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

# No multi-threading in this version ;(
function Update-Gui(){
	$Main.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Background, [action]{})
}

# Define WPF GUI Structure
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
		xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
		Title="Primitive IP Scanner" Height="500" Width="900" Background="#222222" WindowStartupLocation="CenterScreen" ResizeMode="CanMinimize">
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
		<Style x:Key="AlternatingRowStyle" TargetType="{x:Type ListViewItem}" >
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
				<Label Name="BarText" Foreground="#EEEEEE" FontWeight="Bold" Content="Scan" Width="150" Height="30" VerticalAlignment="Stretch" HorizontalAlignment="Stretch" VerticalContentAlignment="Center" HorizontalContentAlignment="Center"/>
			</Grid>
		</Button>
	   <ListView Name="listView" Background="#333333" FontWeight="Bold" HorizontalAlignment="Left" Height="400" Margin="12,49,-140,0" VerticalAlignment="Top" Width="860" VerticalContentAlignment="Top" ScrollViewer.VerticalScrollBarVisibility="Visible" ScrollViewer.CanContentScroll="False" AlternationCount="2" ItemContainerStyle="{StaticResource AlternatingRowStyle}">
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
$reader=(New-Object System.Xml.XmlNodeReader $xaml) 
try{$Main=[Windows.Markup.XamlReader]::Load( $reader )}
catch{Write-Host "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing, PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered."}

# Store Form Objects In PowerShell
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "$($_.Name)" -Value $Main.FindName($_.Name)}

$Main.Add_Closing({[System.Windows.Forms.Application]::Exit();Stop-Process $pid})

$listView.Add_MouseDoubleClick({
	# Scan for shares via Windows Explorer
	$launch = $listView.SelectedItems.HostName
	&explorer "`"\\$launch`""
})



# Define Button Actions
$Scan.Add_MouseEnter({
	$Progress.Background = '#EEEEEE'
	$BarText.Foreground = '#000000'
})

$Scan.Add_MouseLeave({
	$Progress.Background = '#777777'
	$BarText.Foreground = '#000000'
})

$Scan.Add_Click({
	$BarText.Content = 'Please Wait'
	$Scan.IsEnabled = $false
	$global:listview.Items.Clear()
	Update-Gui
	Get-HostInfo
	$Main.Title="Primitive IP Scanner `- `[ External IP: $externalIP `] `- `[ Domain: $domain `]"
	Scan-Subnet
	waitForResponses
	List-Machines
	$BarText.Content = 'Scan'
	$Scan.IsEnabled = $true
})

$global:listview.Items.Clear()

# Show Window
$Main.ShowDialog() | out-null
$appContext=New-Object System.Windows.Forms.ApplicationContext
[void][System.Windows.Forms.Application]::Run($appContext)