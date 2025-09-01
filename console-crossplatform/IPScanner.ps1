# Designed for PS6+ but will run on Windows under PS5.1
$version = $PSVersionTable.PSVersion
if ($version.Major -eq 5 -and $version.Minor -eq 1) {
	$IsWindows = $true
	$IsLinux = $false
	$IsMacOS = $false
}
function Get-HostInfo {
	# Check for elevation on non-Windows
	if (($IsLinux -or $IsMacOS) -and (id -u) -ne 0) {
		Write-Host "This script requires elevated privileges (sudo) on Linux/macOS for network scanning. Please rerun with sudo."
		exit
	}

	# Hostname
	$global:hostName = [System.Net.Dns]::GetHostName()

	# Check Internet Connection and Get External IP
	$ProgressPreference = 'SilentlyContinue'
	$hotspotRedirectionTest = irm "http://www.msftncsi.com/ncsi.txt"
	if ($hotspotRedirectionTest -eq "Microsoft NCSI") {
		$getIPv4Address = ([System.Net.Dns]::GetHostAddresses("ifconfig.me") | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString
		$global:externalIP = Invoke-RestMethod -Uri "https://$getIPv4Address/ip" -Headers @{ Host = "ifconfig.me" }
	} else {
		"No Internet or Redirection"
	}
	$ProgressPreference = 'Continue'

	# OS-specific logic
	if ($IsWindows) {
		# Find Gateway
		$global:gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).NextHop
		$gatewayParts = $gateway -split '\.'
		$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

		# Internal IP
		$global:internalIP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and ($_.IPAddress -like "$gatewayPrefix*") }).IPAddress

		# Host adapter type
		$global:adapter = (Get-NetIPAddress -InterfaceAlias "*Ethernet*","*Wi-Fi*" -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "$gatewayPrefix*" }).InterfaceAlias

		# My Mac
		$global:myMac = (Get-NetAdapter -Name $adapter).MacAddress.Replace('-',':')

		# Convert subnet prefix to readable number
		$prefixLength = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' } | Select-Object -First 1).PrefixLength
		$subnetMask = ([System.Net.IPAddress]::Parse(($([Math]::Pow(2, $prefixLength)) - 1) * [Math]::Pow(2, 32 - $prefixLength))).GetAddressBytes() -join "."

		# Domain
		$domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
	} elseif ($IsLinux) {
		# Find Gateway
		$global:gateway = (ip route show default | Select-String -Pattern 'default via' | ForEach-Object { $_.Line.Split()[2] })
		$gatewayParts = $gateway -split '\.'
		$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

		# Internal IP (find IP on the default interface)
		$defaultInterface = (ip route show default | Select-String -Pattern 'dev' | ForEach-Object { $_.Line.Split()[4] })
		$global:internalIP = (ip addr show $defaultInterface | Select-String -Pattern 'inet ' | ForEach-Object { $_.Line.Trim().Split()[1].Split('/')[0] } | Where-Object { $_ -notlike '127.*' })

		# Host adapter type (interface name)
		$global:adapter = $defaultInterface

		# My Mac
		$global:myMac = (ip link show $defaultInterface | Select-String -Pattern 'link/ether' | ForEach-Object { $_.Line.Trim().Split()[1] })

		# Subnet mask (from CIDR prefix)
		$prefixLength = (ip addr show $defaultInterface | Select-String -Pattern 'inet ' | ForEach-Object { $_.Line.Trim().Split()[1].Split('/')[1] })
		$subnetMask = ([System.Net.IPAddress]::Parse(($([Math]::Pow(2, $prefixLength)) - 1) * [Math]::Pow(2, 32 - $prefixLength))).GetAddressBytes() -join "."

		# Domain (from resolv.conf or hostname)
		$domain = (hostname -d).Trim()
		if ([string]::IsNullOrEmpty($domain)) { $domain = 'Unknown' }
	} elseif ($IsMacOS) {
		# Find Gateway (non-deprecated way)
		$global:gateway = (route -n get default | Select-String -Pattern 'gateway:' | ForEach-Object { $_.Line -replace '.*gateway: ', '' }).Trim()
		$gatewayParts = $gateway -split '\.'
		$global:gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."

		# Default Interface
		$defaultInterface = (route -n get default | Select-String -Pattern 'interface:' | ForEach-Object { $_.Line -replace '.*interface: ', '' }).Trim()

		# Internal IP (non-deprecated way using ipconfig)
		$global:internalIP = (ipconfig getifaddr $defaultInterface)

		# Host adapter type (interface name)
		$global:adapter = $defaultInterface

		# My Mac (using networksetup or ifconfig as fallback)
		$global:myMac = (networksetup -getmacaddress $defaultInterface | Select-String -Pattern 'Ethernet Address:' | ForEach-Object { $_.Line -replace '.*Ethernet Address: ', '' }).Trim()

		# Subnet mask (using ipconfig)
		$subnetMask = (ipconfig getpacket $defaultInterface | Select-String -Pattern 'subnet_mask' | ForEach-Object { $_.Line -replace '.*subnet_mask \(ip\): ', '' }).Trim()

		# Domain (from resolv.conf)
		$domain = (Get-Content /etc/resolv.conf | Select-String -Pattern '^search' | ForEach-Object { $_.Line -replace 'search ', '' }).Trim()
		if ([string]::IsNullOrEmpty($domain)) { $domain = 'Unknown' }
	} else {
		Write-Host "Unsupported OS"
		exit
	}

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

function Get-MacVendor($mac) {
	# Get Vendor via Mac (thanks to u/mprz)
	return (irm "https://www.macvendorlookup.com/api/v2/$($mac.Replace(':','').Substring(0,6))" -Method Get).company
}

function Scan-Subnet {
	# Ping Entire Subnet
	for ($i = 1; $i -le 254; $i++) {
		Test-Connection $gatewayPrefix$i -Count 1 -AsJob | Out-Null
		Write-Progress -Activity "Sending Packets" -Status "Progress..." -PercentComplete ($i * (100 / 254))
	}
	Write-Progress -Activity "Sending Packets" -Status "Done" -PercentComplete 100
	Start-Sleep -Seconds 1
	Write-Progress -Activity "Sending Packets" -Completed
}

function waitForResponses {
	# Wait with progress
	for ($i = 1; $i -le 100; $i++) {
		Write-Progress -Activity "Listening" -Status "Waiting for responses..." -PercentComplete ($i)
		Start-Sleep -Milliseconds 50
	}
	Write-Progress -Activity "Listening" -Status "Done" -PercentComplete 100
	Start-Sleep -Seconds 1
	Write-Progress -Activity "Listening" -Completed
}

function List-Machines {
	# Header
	$DisplayA = ("{0,-18} {1,-26} {2, -14} {3}" -f 'MAC ADDRESS', 'VENDOR', 'IP ADDRESS', 'REMOTE HOSTNAME')
	Write-Host; Write-Host $DisplayA
	Write-Host "================================================================================================="

	# OS-specific ARP table retrieval
	if ($IsWindows) {
		# Filter for Reachable or Stale states and select only IP and MAC address
		$arpInit = Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" -or $_.State -eq "Stale" } | Select-Object -Property IPAddress, LinkLayerAddress
	} elseif ($IsLinux -or $IsMacOS) {
		$arpOutput = if ($IsLinux) { arp -a -n } else { arp -a }
		$arpInit = $arpOutput | ForEach-Object {
			if ($_ -match '\(([\d\.]+)\) at ([\w:]+)') {
				[PSCustomObject]@{
					IPAddress = $matches[1]
					LinkLayerAddress = $matches[2].Replace(':', '-').ToUpper()	# Normalize to Windows format temporarily
				}
			}
		}
	}

	# Convert IP Addresses from string to int by each section
	$arpConverted = $arpInit | Where-Object { $_.IPAddress -match "^\d+\.\d+\.\d+\.\d+$" } | Sort-Object -Property { $ip = $_.IPAddress; [version]($ip) }

	# Sort by IP using [version] sorting
	$arpOutput = $arpConverted | Sort-Object {[version]$_.IPaddress}
	$self = 0
	$myLastOctet = [int]($internalIP -split '\.')[-1]

	# Get My Vendor via Mac lookup
	$tryMyVendor = Get-MacVendor "$myMac"
	$myVendor = if($tryMyVendor){$tryMyVendor.substring(0, [System.Math]::Min(25, $tryMyVendor.Length))} else {'Unknown'}

	# Cycle through ARP table
	foreach ($line in $arpOutput) {
		$ip = $line.IPAddress
		$mac = $line.LinkLayerAddress.Replace('-',':')
		# Get Hostname
		try{
			$name = [System.Net.Dns]::GetHostEntry($ip).HostName
		} catch {
			$name = "Unable to Resolve"
		} finally {
			if ([string]::IsNullOrEmpty($name)) {
				$name = "Unable to Resolve"
			}
		}

		# Get Remote Device Vendor via Mac lookup
		$tryVendor=Get-MacVendor "$mac"
		$vendor = if($tryVendor){$tryVendor.substring(0, [System.Math]::Min(25, $tryVendor.Length))} else {'Unknown'}

		# Format and display
		$DisplayX = ("{0,-18} {1,-26} {2, -14} {3}" -f $mac, $vendor, $ip, $name)
		$DisplayZ = ("{0,-18} {1,-26} {2, -14} {3}" -f $myMac, $myVendor, $internalIP, "$hostName (This Device)")
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

do {
	# Main
	Clear-Host
	Write-Host -NoNewLine 'Getting Ready...'
	Get-HostInfo
	Scan-Subnet
	waitForResponses
	Write-Host 'Done';Write-Host
	$hostOutput | Out-String -Stream | Where-Object { $_.Trim().Length -gt 0 } | Write-Host
	$ProgressPreference = 'SilentlyContinue'
	List-Machines
	$ProgressPreference = 'Continue'
	Write-Host;Write-Host -NoNewLine 'Press any key to refresh, (X) to Exit'
	$Host.UI.RawUI.Flushinputbuffer()
} until ($Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').VirtualKeyCode -eq 88)