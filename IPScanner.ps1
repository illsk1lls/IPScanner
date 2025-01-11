# Generate Admin request. Admin required to clear ARP cache for fresh network list - this is the only task it is required for, line #67
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process Powershell "-nop -c `"iex ([io.file]::ReadAllText(`'$PSCommandPath`'))`"" -Verb RunAs
	exit
}

# Allow Single Instance Only
$AppId = 'IPScanner'
$singleInstance = $false
$script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true,([Threading.EventResetMode]::ManualReset),"Global\$AppId",([ref] $singleInstance)
if (-not $singleInstance){
	$shell = New-Object -ComObject Wscript.Shell
	$shell.Popup("IPScanner is already running!",0,'ERROR:',0x0) | Out-Null
	Exit
}

# Functions
function Get-HostInfo {
	# Hostname
	$global:hostName = hostName

	# Check Internet Connection and Get External IP
	$ProgressPreference='SilentlyContinue'
	$hotspotRedirectionTest = irm "http://www.msftncsi.com/ncsi.txt"
	$global:externalIP = if ($hotspotRedirectionTest -eq "Microsoft NCSI") { 
		irm "http://ifconfig.me/ip"
	} else { 
		"No Internet or Redirection"
	}
	$ProgressPreference='Continue'
	
	# Find Gateway
	$global:gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).NextHop
	$gatewayParts = $gateway -split '\.'
	$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

	# Internal IP
	$global:internalIP = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and ($_.IPAddress -like "$gatewayPrefix*")}).IPAddress

	# Host adapter type
	$global:adapter = (Get-NetIPAddress -InterfaceAlias "*Ethernet*","*Wi-Fi*" -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "$gatewayPrefix*" }).InterfaceAlias

	# My Mac
	$global:myMac = (Get-NetAdapter -Name $adapter).MacAddress

	# Convert subnet prefix to readable number
	$prefixLength = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1'} | Select-Object -First 1).PrefixLength
	$subnetMask = ([System.Net.IPAddress]::Parse(($([Math]::Pow(2, $prefixLength)) - 1) * [Math]::Pow(2, 32 - $prefixLength))).GetAddressBytes() -join "."

	# Domain
	$global:domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain

	# Output results
	$global:hostOutput = [PSCustomObject]@{
		Host = if($hostName){$hostName} else {'Unknown'}
		ExternalIP = if($externalIP){$externalIP} else {'Unknown'}
		InternalIP = if($internalIP){$internalIP} else {'Unknown'}
		Adapter = if($adapter){$adapter} else {'Unknown'}
		Subnet = if($subnetMask){$subnetMask} else {'Unknown'}
		Gateway = if($gateway){$gateway} else {'Unknown'}
		Domain = if($domain){$domain} else {'Unknown'}
	}
}

function Scan-Subnets {
	# Clear ARP cache - Requires Admin
	Remove-NetNeighbor -InterfaceAlias "$adapter" -AsJob -Confirm:$false | Out-Null

	# Ping Entire Subnet
	for ($i = 1; $i -le 254; $i++) {
		Test-Connection $gatewayPrefix$i -Count 1 -AsJob | Out-Null
		Write-Progress -Activity "Sending Packets" -Status "Progress..." -PercentComplete ($i * (100 / 254))
	}
	Write-Progress -Activity "Sending Packets" -Status "Complete!" -PercentComplete 100
	Start-Sleep -Seconds 1
	Write-Progress -Activity "Sending Packets" -Completed
}

function List-Machines {
	$DisplayA = ("{0,-20} {1,-18} {2}" -f 'MAC ADDRESS', 'IP ADDRESS', 'REMOTE HOSTNAME')
	Write-Host; Write-Host $DisplayA
	Write-Host "==============================================================================="

	# Filter for Reachable or Stale states and select only IP and MAC address
	$arpOutput = Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" -or $_.State -eq "Stale" } | Select-Object -Property IPAddress, LinkLayerAddress | Sort-Object -Property IPAddress
	$self = 0
	$myLastOctet = [int]($internalIP -split '\.')[-1]

	foreach ($line in $arpOutput) {
		$ip = $line.IPAddress
		$mac = $line.LinkLayerAddress
		$name = try {
			([System.Net.Dns]::GetHostEntry($ip)).HostName
		} catch {
			"Unable to Resolve"
		}

		# Format and display
		$DisplayX = ("{0,-20} {1,-18} {2}" -f $mac, $ip, $name)
		$DisplayZ = ("{0,-20} {1,-18} {2}" -f $myMac, $internalIP, "$hostName (This Device)")
		$lastOctet = [int]($ip -split '\.')[-1]
		if ($myLastOctet -gt $lastOctet) {
			Write-Host $DisplayX
		} else {
			if ($self -ge 1) {
				Write-Host $DisplayX
			} else {
				Write-Host $DisplayZ
				Write-Host $DisplayX
				$self++
			}
		}
	}
}

# Main
do {
	Clear-Host
	Write-Host -NoNewLine 'Getting Ready...'
	Get-HostInfo
	Scan-Subnets
	Write-Host 'Done';Write-Host
	$hostOutput | Out-String -Stream | Where-Object { $_.Trim().Length -gt 0 } | Write-Host
	List-Machines
	Write-Host;Write-Host -NoNewLine 'Press any key to refresh, (X) to Exit'
	$Host.UI.RawUI.Flushinputbuffer()
} until ($Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').VirtualKeyCode -eq 88)