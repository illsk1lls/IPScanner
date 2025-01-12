function Check-WebInterface {
    param (
        [string]$hostname
    )
$checkForInterface = "$hostname"
$TCPClient = [System.Net.Sockets.TcpClient]::new()
$Result = $TCPClient.ConnectAsync($checkForInterface, 80).Wait(250)
$TCPClient.Close()
write-host $result
}

# Usage
Check-WebInterface -hostname "192.168.1.1"

cmd /c pause