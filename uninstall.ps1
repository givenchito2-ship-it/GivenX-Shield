#Requires -RunAsAdministrator
$install=Join-Path $env:ProgramFiles 'GivenX Shield'
Get-Process 'GivenX.Agent','GivenX.UI' -ErrorAction SilentlyContinue|Stop-Process -Force
Unregister-ScheduledTask -TaskName 'GivenX Shield Agent' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'GivenX Shield UI' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'GivenX Shield Watchdog' -Confirm:$false -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName 'GivenX Shield *' -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'GivenX Shield.lnk') -Force -ErrorAction SilentlyContinue
$sysmonExe=Join-Path $install 'engines\sysmon\Sysmon64.exe';$sysmonMarker=Join-Path $install 'engines\sysmon\installed-by-givenx.txt'
if((Test-Path $sysmonMarker)-and(Test-Path $sysmonExe)){& $sysmonExe -accepteula -u|Out-Null}
if(Test-Path $install){Remove-Item $install -Recurse -Force}
Write-Host 'GivenX Shield fue desinstalado y se retiraron sus reglas de Firewall. El historial en ProgramData se conservó. Un Sysmon preexistente no se modifica.' -ForegroundColor Yellow
