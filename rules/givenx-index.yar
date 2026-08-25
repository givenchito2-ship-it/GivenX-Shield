rule GivenX_Suspicious_PowerShell_Downloader {
  meta: description = "Script con varias técnicas habituales de descarga y ejecución" severity = "high"
  strings:
    $a = "FromBase64String" nocase
    $b = "DownloadString" nocase
    $c = "Invoke-Expression" nocase
    $d = "Net.WebClient" nocase
    $e = "-EncodedCommand" nocase
  condition: 2 of them
}

rule GivenX_Safe_SelfTest {
  meta: description = "Marcador inofensivo para comprobar el motor YARA de GivenX" severity = "test"
  strings:
    $marker = "GIVENX_SAFE_SELF_TEST_1_6" ascii wide
  condition: $marker
}

rule GivenX_Possible_Keylogger_APIs {
  meta: description = "Combinación de APIs frecuentemente usada por registradores de teclado" severity = "review"
  strings:
    $a = "GetAsyncKeyState" ascii wide
    $b = "SetWindowsHookEx" ascii wide
    $c = "GetForegroundWindow" ascii wide
    $d = "GetKeyboardState" ascii wide
  condition: 3 of them
}

rule GivenX_Possible_InfoStealer_Targets {
  meta: description = "Archivo que referencia varios almacenes de credenciales y sesiones" severity = "review"
  strings:
    $a = "Login Data" ascii wide
    $b = "Local State" ascii wide
    $c = "Cookies" ascii wide
    $d = "wallet.dat" ascii wide
    $e = "discord\\Local Storage\\leveldb" ascii wide nocase
  condition: 3 of them
}

rule GivenX_Possible_Credential_Dumper {
  meta: description = "Referencias combinadas a volcado de credenciales de Windows" severity = "high"
  strings:
    $a = "sekurlsa::logonpasswords" ascii wide nocase
    $b = "lsass.dmp" ascii wide nocase
    $c = "MiniDumpWriteDump" ascii wide
    $d = "comsvcs.dll" ascii wide nocase
    $e = "LsaUnprotectMemory" ascii wide
  condition: 2 of them
}

rule GivenX_Possible_Process_Injection {
  meta: description = "Combinación de APIs utilizada para inyectar código en otros procesos" severity = "review"
  strings:
    $a = "VirtualAllocEx" ascii wide
    $b = "WriteProcessMemory" ascii wide
    $c = "CreateRemoteThread" ascii wide
    $d = "QueueUserAPC" ascii wide
    $e = "NtUnmapViewOfSection" ascii wide
  condition: 3 of them
}

rule GivenX_Possible_Browser_Stealer {
  meta: description = "Acceso combinado a almacenes y descifrado de credenciales del navegador" severity = "high"
  strings:
    $a = "\\Google\\Chrome\\User Data" ascii wide nocase
    $b = "\\Microsoft\\Edge\\User Data" ascii wide nocase
    $c = "CryptUnprotectData" ascii wide
    $d = "Login Data" ascii wide
    $e = "Local State" ascii wide
    $f = "encrypted_key" ascii wide
  condition: 4 of them
}

rule GivenX_Possible_RAT_Capabilities {
  meta: description = "Capacidades combinadas asociadas a herramientas de acceso remoto maliciosas" severity = "review"
  strings:
    $a = "GetAsyncKeyState" ascii wide
    $b = "BitBlt" ascii wide
    $c = "TcpClient" ascii wide
    $d = "CreateRemoteThread" ascii wide
    $e = "\\CurrentVersion\\Run" ascii wide nocase
    $f = "GetForegroundWindow" ascii wide
  condition: 4 of them
}

rule GivenX_Possible_Crypto_Miner {
  meta: description = "Indicadores combinados de minería no autorizada" severity = "review"
  strings:
    $a = "stratum+tcp://" ascii wide nocase
    $b = "stratum+ssl://" ascii wide nocase
    $c = "donate-level" ascii wide nocase
    $d = "randomx" ascii wide nocase
    $e = "xmrig" ascii wide nocase
  condition: 3 of them
}

rule GivenX_Possible_Ransomware_Recovery_Tampering {
  meta: description = "Comandos combinados usados para impedir recuperación después de cifrado" severity = "high"
  strings:
    $a = "vssadmin delete shadows" ascii wide nocase
    $b = "wmic shadowcopy delete" ascii wide nocase
    $c = "wbadmin delete catalog" ascii wide nocase
    $d = "recoveryenabled no" ascii wide nocase
    $e = "bootstatuspolicy ignoreallfailures" ascii wide nocase
  condition: 2 of them
}

rule GivenX_Possible_Security_Tampering {
  meta: description = "Script que intenta desactivar protección o agregar exclusiones" severity = "high"
  strings:
    $a = "DisableRealtimeMonitoring" ascii wide nocase
    $b = "Add-MpPreference" ascii wide nocase
    $c = "ExclusionPath" ascii wide nocase
    $d = "sc stop WinDefend" ascii wide nocase
    $e = "GivenX Shield Agent" ascii wide nocase
    $f = "Unregister-ScheduledTask" ascii wide nocase
  condition: 2 of them
}

rule GivenX_Possible_Discord_Token_Stealer {
  meta: description = "Referencias combinadas a almacenamiento y uso de tokens de Discord" severity = "high"
  strings:
    $a = "discord\\Local Storage\\leveldb" ascii wide nocase
    $b = "discord.com/api/v" ascii wide nocase
    $c = "Authorization" ascii wide
    $d = "mfa." ascii wide
    $e = "dQw4w9WgXcQ" ascii wide
  condition: 3 of them
}

rule GivenX_Possible_Browser_Cookie_Theft {
  meta: description = "Acceso combinado a cookies de navegadores y claves DPAPI" severity = "high"
  strings:
    $a = "\\Network\\Cookies" ascii wide nocase
    $b = "\\User Data\\Default\\Cookies" ascii wide nocase
    $c = "CryptUnprotectData" ascii wide
    $d = "encrypted_value" ascii wide
    $e = "Local State" ascii wide
  condition: 3 of them
}

rule GivenX_Possible_Lolbin_Downloader {
  meta: description = "Uso combinado de herramientas de Windows para descargar o ejecutar contenido" severity = "review"
  strings:
    $a = "certutil -urlcache" ascii wide nocase
    $b = "bitsadmin /transfer" ascii wide nocase
    $c = "mshta http" ascii wide nocase
    $d = "regsvr32 /s /n /u /i:http" ascii wide nocase
    $e = "rundll32 javascript:" ascii wide nocase
    $f = "Invoke-WebRequest" ascii wide nocase
  condition: 2 of them
}

rule GivenX_Possible_Persistence_Script {
  meta: description = "Script con varios mecanismos de persistencia de Windows" severity = "review"
  strings:
    $a = "schtasks /create" ascii wide nocase
    $b = "Register-ScheduledTask" ascii wide nocase
    $c = "\\CurrentVersion\\Run" ascii wide nocase
    $d = "\\Programs\\Startup" ascii wide nocase
    $e = "__EventFilter" ascii wide
    $f = "CommandLineEventConsumer" ascii wide
  condition: 2 of them
}

rule GivenX_Possible_Bot_C2_Loop {
  meta: description = "Capacidades combinadas compatibles con un bucle de mando y control" severity = "review"
  strings:
    $a = "TcpClient" ascii wide
    $b = "GetHostName" ascii wide
    $c = "ProcessStartInfo" ascii wide
    $d = "FromBase64String" ascii wide
    $e = "Thread.Sleep" ascii wide
    $f = "ReceiveBufferSize" ascii wide
  condition: 4 of them
}

rule GivenX_Possible_Clipboard_Crypto_Hijacker {
  meta: description = "Capacidades combinadas para vigilar y reemplazar direcciones en el portapapeles" severity = "review"
  strings:
    $a = "GetClipboardData" ascii wide
    $b = "SetClipboardData" ascii wide
    $c = "OpenClipboard" ascii wide
    $d = "bitcoin" ascii wide nocase
    $e = "ethereum" ascii wide nocase
    $f = "clipboard" ascii wide nocase
  condition: 4 of them
}

rule GivenX_Possible_Hidden_Proxy_Tunnel {
  meta: description = "Capacidades combinadas de proxy, túnel o redirección oculta" severity = "review"
  strings:
    $a = "SOCKS5" ascii wide nocase
    $b = "TcpListener" ascii wide
    $c = "PortForward" ascii wide nocase
    $d = "ReverseProxy" ascii wide nocase
    $e = "ReceiveBufferSize" ascii wide
    $f = "NetworkStream" ascii wide
  condition: 4 of them
}

rule GivenX_Possible_Browser_Extension_Theft {
  meta: description = "Acceso combinado a extensiones, sesiones y descifrado del navegador" severity = "high"
  strings:
    $a = "\\User Data\\Default\\Extensions" ascii wide nocase
    $b = "Local Extension Settings" ascii wide nocase
    $c = "manifest.json" ascii wide nocase
    $d = "CryptUnprotectData" ascii wide
    $e = "Login Data" ascii wide
    $f = "Local State" ascii wide
  condition: 4 of them
}

rule GivenX_Possible_Service_Persistence {
  meta: description = "Creación combinada de servicio persistente con inicio automático" severity = "review"
  strings:
    $a = "CreateServiceW" ascii wide
    $b = "StartServiceW" ascii wide
    $c = "SERVICE_AUTO_START" ascii wide
    $d = "sc create" ascii wide nocase
    $e = "New-Service" ascii wide nocase
    $f = "StartType Automatic" ascii wide nocase
  condition: 3 of them
}
