# Generate Admin request. Admin required to clear ARP cache for fresh network list - this is the only task it is required for, line #66
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process powershell.exe "-nop -ep bypass -f `"$PSCommandPath`"" -Verb RunAs
	exit
}

# Allow Single Instance Only
$AppId = 'IPScanner'
$singleInstance = $false
$script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true,([Threading.EventResetMode]::ManualReset),"Global\IPScanner",([ref] $singleInstance)
if (-not $singleInstance){
	$shell = New-Object -ComObject Wscript.Shell
	$shell.Popup("IPScanner is already running!",0,'ERROR:',0x0) | Out-Null
	Exit
}

# Functions
function Get-HostInfo {
	# Hostname
	$global:hostName = $env:COMPUTERNAME

	# Check Internet Connection and Get External IP
	$pingTest = Test-Connection -ComputerName "ifconfig.me" -Count 1 -Quiet
	$global:externalIP = if ($pingTest) { 
		(Invoke-WebRequest -Uri "http://ifconfig.me/ip" -UseBasicParsing).Content.Trim() 
	} else { 
		"No Internet Detected" 
	}

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
	$domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
	$global:domain = if ([string]::IsNullOrEmpty($domain)) { "Unknown" } else { $domain }

	# Output results
	$global:hostOutput = [PSCustomObject]@{
		Host = $hostName
		ExternalIP = $externalIP
		InternalIP = $internalIP
		Adapter = $adapter
		Subnet = $subnetMask
		Gateway = $gateway
		Domain = $domain
	}
}

function Scan-Subnets {
	# Clear ARP cache - Requires Admin
	netsh interface ipv4 delete neighbors | Out-Null
	
	# Scan Interfaces
	$arpOutput = arp -a | Out-String
	$lines = $arpOutput -split '\r?\n'

	foreach ($line in $lines) {
		if ($line -match 'Interface: (\d+\.\d+\.\d+\.\d+)') {
			$interfaceIP = $matches[1]
			$ipParts = $interfaceIP -split '\.'
			$scanPrefix = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])."
			if ($gatewayPrefix -eq $scanPrefix) {
				for ($i = 1; $i -le 254; $i++) {
					Test-Connection $scanPrefix$i -Count 1 -AsJob | Out-Null
					Write-Progress -Activity "Sending Packets" -Status "Progress..." -PercentComplete ($i * (100 / 254))
				}
				Write-Progress -Activity "Sending Packets" -Status "Complete!" -PercentComplete 100
				Start-Sleep -Seconds 1
			}
		}
	}
	Write-Progress -Activity "Sending Packets" -Completed
}

function List-Machines {
	Write-Host ""
	Write-Host "MAC ADDRESS          IP ADDRESS         REMOTE HOSTNAME"
	Write-Host "==============================================================================="

	# Display refreshed ARP table information
	$arpOutput = arp -a | Out-String
	$lines = $arpOutput -split '\r?\n'
	$self = 0
	$myLastOctet = 0

	foreach ($line in $lines) {
		if ($line -match 'Interface: (\d+\.\d+\.\d+\.\d+)') {
			$myIP = $matches[1]
			$myLastOctet = [int]($myIP -split '\.')[-1]
		} elseif ($line -match '(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+dynamic') {
			$ip = $matches[1]
			$mac = $matches[2]
			$name = try {
				([System.Net.Dns]::GetHostEntry($ip)).HostName
			} catch {
				"Unable to Resolve"
			}

			# Format and display
			$ipFormatted = "{0,-15}" -f $ip
			$lastOctet = [int]($ip -split '\.')[-1]
			if ($myLastOctet -gt $lastOctet) {
				Write-Host ("{0,-20} {1,-18} {2}" -f $mac, $ipFormatted, $name)
			} else {
				if ($self -ge 1) {
					Write-Host ("{0,-20} {1,-18} {2}" -f $mac, $ipFormatted, $name)
				} else {
					Write-Host ("{0,-20} {1,-18} {2}" -f $myMac, $myIP, "$hostName (This Device)")
					Write-Host ("{0,-20} {1,-18} {2}" -f $mac, $ipFormatted, $name)
					$self++
				}
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