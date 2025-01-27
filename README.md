<h1 align="center">Simple IP Scanner - A Powershell/CMD Hybrid Network Scanner</h1>

<p align="center"><img src="https://github.com/illsk1lls/IPScanner/blob/main/.readme/IPScanner.png?raw=true"></p>

<p align="center"><sup align="center">This script will work as either a .CMD or .PS1 file.<br>
(For ease of use it will be posted as a CMD file, as you can simply Double-Click it to launch)</sup></p>

For use with basic networks to get an up to date list of client: MAC Address, Vendor, IP Address, and Hostnames<br>

External IP Address and Domain are also displayed in the titlebar after initiating a scan<br>

Right click the scan button to change subnets

<p align="center"><img src="https://github.com/illsk1lls/IPScanner/blob/main/.readme/ScanContextSubnet.png?raw=true"></p>

Double-clicking a listed item will give you a pop-up showing available connection options to that device.  Clickable buttons will appear for available options. 

<p align="center"><img src="https://github.com/illsk1lls/IPScanner/blob/main/.readme/DoubleClickPopup.png?raw=true"></p>

Right clicking the pop-up will produce CopyToClipboard options.<br>

<p align="center"><img src="https://github.com/illsk1lls/IPScanner/blob/main/.readme/CopyItemToClip.png?raw=true"></p>

Right-Click anywhere in the ListView window for Export options of the current list. (HTML example export shown)

<p align="center"><img src="https://github.com/illsk1lls/IPScanner/blob/main/.readme/ContextMenuExport.png?raw=true"></p>

<p align="center"><img src="https://github.com/illsk1lls/IPScanner/blob/main/.readme/HTMLexample-export.png?raw=true"></p>

**If you wish to clear your cached list of network peers (ARP Cache) prior to scanning the network, hold the \[CTRL\] key while clicking the Scan button<br>**
**(Note: Clearing network peer cache requires Admin rights, while normal scanning/usage does not. A UAC prompt will be produced for this action if needed.)**