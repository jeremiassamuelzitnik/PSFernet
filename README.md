# PSFernet
For using PSFernet you can use this commands with this parameters.

Import-Module -Path .\fernet.psm1
Get-AES256Key (no parameters)
Invoke-EncryptAES256 -KeyBase64 -Message
Invoke-DecryptAES256 -KeyBase64 -token -MaxAgeSeconds (default 0)
