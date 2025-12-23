# AES-256-CBC + HMAC-SHA256 in PowerShell (PS 5.1 or greater)
# Key: 48 bytes base64 (16 signing + 32 encryption)
# Token: base64(version + timestamp + IV + ciphertext + HMAC) URL-safe
function Generate-AES256Key {
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $keyBytes = New-Object byte[] 48  # 16 para HMAC + 32 para AES-256
    $rng.GetBytes($keyBytes)
    return [Convert]::ToBase64String($keyBytes)
}
function Encrypt-AES256 {
    param (
        [string]$KeyBase64,
        [string]$Message
    )
    $keyBytes = [Convert]::FromBase64String($KeyBase64)
    if ($keyBytes.Length -ne 48) {
        throw "Key must be 48 bytes base64 (16 signing + 32 encryption)."
    }
    $signingKey = $keyBytes[0..15]
    $encryptionKey = $keyBytes[16..47]
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $iv = New-Object byte[] 16
    $rng.GetBytes($iv)
    # Timestamp big-endian
    $timestamp = [long]((Get-Date).ToUniversalTime() - (New-Object DateTime 1970,1,1)).TotalSeconds
    $timestampBytes = New-Object byte[] 8
    for ($i = 7; $i -ge 0; $i--) {
        $timestampBytes[$i] = [byte]($timestamp -band 0xFF)
        $timestamp = $timestamp -shr 8
    }
    # Cifrado AES-256-CBC
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.KeySize = 256
    $aes.Key = $encryptionKey
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $encryptor = $aes.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)
    # HMAC
    $versionByte = [byte]0x80
    $dataToSign = @($versionByte) + $timestampBytes + $iv + $ciphertext
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $signingKey
    $hmacBytes = $hmac.ComputeHash($dataToSign)
    # Token
    $tokenBytes = @($versionByte) + $timestampBytes + $iv + $ciphertext + $hmacBytes
    $token = [Convert]::ToBase64String($tokenBytes) -replace '\+', '-' -replace '/', '_' -replace '=', ''
    return $token
}
function Decrypt-AES256 {
    param (
        [string]$KeyBase64,
        [string]$Token,
        [long]$MaxAgeSeconds = 0
    )
    $keyBytes = [Convert]::FromBase64String($KeyBase64)
    if ($keyBytes.Length -ne 48) {
        throw "Key must be 48 bytes base64."
    }
    $signingKey = $keyBytes[0..15]
    $encryptionKey = $keyBytes[16..47]
    # Restore base64
    $token = $token -replace '-', '+' -replace '_', '/'
    $padding = (4 - ($token.Length % 4)) % 4
    $token += '=' * $padding
    $tokenBytes = [Convert]::FromBase64String($token)
    if ($tokenBytes.Length -lt 73) { throw "Token inválido." }  # mínimo ajustado
    $versionByte = $tokenBytes[0]
    if ($versionByte -ne 0x80) { throw "Versión inválida." }
    $timestampBytes = $tokenBytes[1..8]
    $iv = $tokenBytes[9..24]
    $hmacBytes = $tokenBytes[($tokenBytes.Length-32)..($tokenBytes.Length-1)]
    $ciphertext = $tokenBytes[25..($tokenBytes.Length-33)]
    # Verificar HMAC (tiempo constante)
    $dataToSign = $tokenBytes[0..($tokenBytes.Length-33)]
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $signingKey
    $computedHmac = $hmac.ComputeHash($dataToSign)
    $diff = 0
    for ($i = 0; $i -lt 32; $i++) {
        $diff = $diff -bor ($computedHmac[$i] -bxor $hmacBytes[$i])
    }
    if ($diff -ne 0) { throw "HMAC inválido." }
    # TTL opcional
    if ($MaxAgeSeconds -gt 0) {
        $timestamp = 0
        for ($i = 0; $i -lt 8; $i++) { $timestamp = ($timestamp -shl 8) + $timestampBytes[$i] }
        $current = [long]((Get-Date).ToUniversalTime() - (New-Object DateTime 1970,1,1)).TotalSeconds
        if (($current - $timestamp) -gt $MaxAgeSeconds) { throw "Token expirado." }
    }
    # Desencriptar
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.KeySize = 256
    $aes.Key = $encryptionKey
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $decryptor = $aes.CreateDecryptor()
    $plaintextBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    return [System.Text.Encoding]::UTF8.GetString($plaintextBytes)
}
