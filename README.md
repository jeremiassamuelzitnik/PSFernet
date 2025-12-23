# PSFernet

Import Module:

Import-Module -Path .\fernet.psm1

To use PSFernet, run the following commands with these parameters:

Get-AES256Key (no parameters)

Invoke-EncryptAES256 -KeyBase64 -Message

Invoke-DecryptAES256 -KeyBase64 -token -MaxAgeSeconds (default 0)
