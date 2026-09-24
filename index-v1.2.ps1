<#
.SYNOPSIS
    Coleta evidências locais de estação AR (v2 - corrigido).
.DESCRIPTION
    Executa verificações filtradas. A data e hora são validadas exibindo
    abertamente a digitação e execução dos comandos no console para
    total transparência na auditoria.

    CORREÇÕES v2:
    - Corrigido bug de buffering do Start-Transcript: toda saída de comando
      é capturada via Out-String e reemitida via Write-Host, garantindo
      ordem correta no transcript e nos screenshots.
    - Corrigido filtro do auditpol (Logon$ -> Logon) e removido placeholder
      literal <categorias_filtradas> do prompt exibido.
    - Valores de registro ausentes agora aparecem como 'AUSENTE' em vez
      de ficarem em branco.
.PARAMETER ScreenshotFolder
    Pasta onde os prints serão salvos (padrão: C:\Temp\EvidenciasAR).
#>
param (
    [string]$ScreenshotFolder = "C:\Temp\EvidenciasAR"
)

# Forçar STA e carregar assemblies de UI
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null

# Preparar diretório
if (-not (Test-Path $ScreenshotFolder)) {
    New-Item -ItemType Directory -Path $ScreenshotFolder -Force | Out-Null
}

# Iniciar transcrição para log texto
$logPath = Join-Path $ScreenshotFolder "Evidencias_AR_Final_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logPath -Append

# ------------------------------------------------------------------
# FUNÇÕES AUXILIARES
# ------------------------------------------------------------------

# Maximiza janela do console
function Set-MaxConsoleSize {
    try {
        $console = $Host.UI.RawUI
        $maxWindowSize = $console.MaxWindowSize
        $console.WindowSize = $maxWindowSize
        $console.BufferSize = $maxWindowSize
    } catch {
        Write-Host "Nao foi possivel redimensionar o console automaticamente. Reduza a fonte manualmente (Ctrl + Scroll Down)." -ForegroundColor Yellow
    }
}
Set-MaxConsoleSize

# Screenshot da tela inteira
function Capture-Screen {
    param([string]$FileName)

    $path = Join-Path $ScreenshotFolder $FileName
    $screenBounds = [System.Windows.Forms.SystemInformation]::VirtualScreen

    $bitmap = New-Object System.Drawing.Bitmap $screenBounds.Width, $screenBounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($screenBounds.Left, $screenBounds.Top, 0, 0, $screenBounds.Size)
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)

    $graphics.Dispose()
    $bitmap.Dispose()

    Write-Host "Screenshot salvo: $path" -ForegroundColor Cyan
}

# Cabeçalho compacto
function Write-RequirementHeader {
    param([string]$Codigo, [string]$Descricao)

    & { Get-Date | Out-Host }
    $Host.UI.RawUI.FlushInputBuffer()
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 500

    $Serial = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
    $Usuario = "$($env:USERDOMAIN)\$($env:USERNAME)"
    Clear-Host

    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "$Codigo - $Descricao" -ForegroundColor Green
    Write-Host "hostname: $(hostname)  |  Serial: $Serial" -ForegroundColor Cyan
    Write-Host "Usuario: $Usuario  |  $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Yellow
}

# Aguarda flush antes do print
function Wait-ForScreen {
    & { Get-Date | Out-Host }
    $Host.UI.RawUI.FlushInputBuffer()
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 300
}

# Escreve texto capturado via Write-Host (information stream), garantindo
# ordem correta no Start-Transcript e nos screenshots.
function Write-Captured {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }
    Write-Host $Text.TrimEnd()
}

# ==================================================================
#  1. Criptografia de disco
# ==================================================================
Write-RequirementHeader -Codigo "4.1.1.1" -Descricao "Criptografia de disco (BitLocker)"
Write-Host "PS C:\> manage-bde -status`n" -ForegroundColor White
$out = (manage-bde -status 2>&1 | Out-String)
Write-Captured $out
Wait-ForScreen
Capture-Screen -FileName "01_Criptografia_BitLocker.png"

# ==================================================================
#  2. Diretiva de Senha
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(b)" -Descricao "Diretivas de senha"
Write-Host "PS C:\> net accounts`n" -ForegroundColor White
$out = (net accounts 2>&1 | Out-String)
Write-Captured $out
Wait-ForScreen
Capture-Screen -FileName "02_Politica_Senha.png"

# ==================================================================
#  3. Diretiva de Bloqueio de Conta
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(b.2)" -Descricao "Diretiva de bloqueio de conta"

$SecPolFile = Join-Path $env:TEMP "security_policy_ar.txt"
Write-Host "PS C:\> secedit /export /cfg $SecPolFile /areas SECURITYPOLICY" -ForegroundColor White
secedit /export /cfg $SecPolFile /areas SECURITYPOLICY | Out-Null

Write-Host "PS C:\> Get-Content `$SecPolFile | Select-String 'Lockout'`n" -ForegroundColor White
$out = (Get-Content $SecPolFile | Select-String "Lockout" | Out-String)
Write-Captured $out

Remove-Item $SecPolFile -ErrorAction SilentlyContinue
Wait-ForScreen
Capture-Screen -FileName "03_Diretiva_Bloqueio_Conta.png"

# ==================================================================
#  4. Antivírus
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(d)" -Descricao "Estado do Microsoft Defender Antivirus"
Write-Host "PS C:\> Get-MpComputerStatus | Select-Object AntivirusEnabled, ...`n" -ForegroundColor White
$out = (Get-MpComputerStatus |
        Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled,
                      OnAccessProtectionEnabled, AntispywareEnabled, AntivirusSignatureLastUpdated |
        Format-Table -AutoSize | Out-String)
Write-Captured $out
Wait-ForScreen
Capture-Screen -FileName "04_Antivirus.png"

# ==================================================================
#  5. Firewall
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(e)" -Descricao "Firewall do Windows (perfis e ações)"
Write-Host "PS C:\> Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction`n" -ForegroundColor White
$out = (Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Format-Table -AutoSize | Out-String)
Write-Captured $out
Wait-ForScreen
Capture-Screen -FileName "05_Firewall.png"

# ==================================================================
#  6. Serviço NTP — condensado (2 blocos)
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(j)" -Descricao "Configuração NTP / sincronismo de hora"

Write-Host "PS C:\> w32tm /query /configuration | Select-String 'Type|NtpServer|Enabled'" -ForegroundColor White
$out = (w32tm /query /configuration 2>&1 | Select-String -Pattern "Type|NtpServer|Enabled" | Out-String)
Write-Captured $out

Write-Host "`nPS C:\> w32tm /query /status ; w32tm /query /source" -ForegroundColor White
$out = (w32tm /query /status 2>&1 | Out-String)
Write-Captured $out
$outSrc = (w32tm /query /source 2>&1 | Out-String)
Write-Host "Fonte NTP: $($outSrc.Trim())"

Wait-ForScreen
Capture-Screen -FileName "06_Servico_NTP.png"

# ==================================================================
#  7. Acesso remoto (RDP) desabilitado — condensado
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(i)" -Descricao "Acesso remoto (RDP) desabilitado"

Write-Host "PS C:\> Get-ItemProperty 'HKLM:\...\Terminal Server' -Name fDenyTSConnections" -ForegroundColor White
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
Write-Host "fDenyTSConnections = $($rdp.fDenyTSConnections)"

Write-Host "`nPS C:\> Get-ItemProperty 'HKLM:\...\RDP-Tcp' -Name PortNumber" -ForegroundColor White
$porta = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
Write-Host "PortNumber_RDP = $($porta.PortNumber)"

Write-Host "`nPS C:\> Get-Service TermService | Select Status,StartType" -ForegroundColor White
$out = (Get-Service TermService -ErrorAction SilentlyContinue |
        Select-Object Status, StartType |
        Format-Table -AutoSize | Out-String)
Write-Captured $out

Write-Host "`n--- Interpretacao: RDP $(
    if ($rdp.fDenyTSConnections -eq 1) { "desabilitado" }
    elseif ($rdp.fDenyTSConnections -eq 0) { "HABILITADO" }
    else { "indeterminado" }
) (fDenyTSConnections=$($rdp.fDenyTSConnections))" -ForegroundColor $(if ($rdp.fDenyTSConnections -eq 1) { "Green" } elseif ($rdp.fDenyTSConnections -eq 0) { "Red" } else { "Yellow" })

Wait-ForScreen
Capture-Screen -FileName "07_RDP_Desabilitado.png"

# ==================================================================
#  8. Especificações do Windows / Ativação
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(g/h)" -Descricao "Especificacoes do Windows (Software Autentico)"

Write-Host "PS C:\> Get-CimInstance Win32_OperatingSystem`n" -ForegroundColor White
$WmiOS = Get-CimInstance Win32_OperatingSystem
$RegOS = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

$out = ([PSCustomObject]@{
    "Edição"           = ($WmiOS.Caption).Replace("Microsoft ", "")
    "Versão"           = $RegOS.DisplayVersion
    "Instalado em"     = $WmiOS.InstallDate.ToString("dd/MM/yyyy")
    "Compilação do SO" = "$($RegOS.CurrentBuild).$($RegOS.UBR)"
} | Format-Table -AutoSize | Out-String)
Write-Captured $out

Write-Host "PS C:\> cscript //nologo slmgr.vbs /xpr`n" -ForegroundColor White
$out = (cscript //nologo C:\Windows\System32\slmgr.vbs /xpr 2>&1 | Out-String)
Write-Captured $out

Write-Host "`nPS C:\> cscript //nologo slmgr.vbs /dli (resumido)`n" -ForegroundColor White
$out = (cscript //nologo C:\Windows\System32\slmgr.vbs /dli 2>&1 |
        Select-String -Pattern "Nome|Descrição|Status|Product Key Channel|License Status|Genuine|Name|Description|License" -SimpleMatch |
        Out-String)
Write-Captured $out

Wait-ForScreen
Capture-Screen -FileName "08_Especificacoes_Windows.png"

# ==================================================================
#  9. Sistema Atualizado - Update
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(g)" -Descricao "Status do Windows Update"

Write-Host "PS C:\> Get-Service wuauserv | Select-Object Status, StartType`n" -ForegroundColor White
$svc = Get-Service wuauserv -ErrorAction SilentlyContinue

if ($svc) {
    # Traduz Status do serviço
    $mapStatus = @{
        'Running'       = 'Em execução'
        'Stopped'       = 'Parado'
        'Paused'        = 'Pausado'
        'StartPending'  = 'Iniciando'
        'StopPending'   = 'Parando'
        'ContinuePending' = 'Continuando'
        'PausePending'  = 'Pausando'
    }
    # Traduz Tipo de inicialização
    $mapStart = @{
        'Automatic'             = 'Automático'
        'AutomaticDelayedStart' = 'Automático (atraso)'
        'Manual'                = 'Manual'
        'Disabled'              = 'Desabilitado'
        'Boot'                  = 'Boot'
        'System'                = 'System'
    }

    $statusRaw = $svc.Status.ToString()
    $startRaw  = $svc.StartType.ToString()
    $statusTxt = if ($mapStatus.ContainsKey($statusRaw)) { $mapStatus[$statusRaw] } else { $statusRaw }
    $startTxt  = if ($mapStart.ContainsKey($startRaw))   { $mapStart[$startRaw] }   else { $startRaw }

    $out = ([PSCustomObject]@{
        'Servico'              = $svc.Name
        'Nome de exibicao'     = $svc.DisplayName
        'Tipo de Servico'      = $statusTxt
        'Tipo de Inicializacao'= $startTxt
    } | Format-List | Out-String)
    Write-Captured $out
} else {
    Write-Host "Servico wuauserv NAO ENCONTRADO neste host." -ForegroundColor Red
}

Write-Host "`nPS C:\> Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 2`n" -ForegroundColor White
$out = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 2 | Format-Table -AutoSize | Out-String)
Write-Captured $out

Wait-ForScreen
Capture-Screen -FileName "09_Windows_Update.png"

# ==================================================================
#  10. Proteção de Tela e Bloqueio de Sessão
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(f)" -Descricao "Protecao de Tela e Bloqueio de Sessao"

Write-Host "PS C:\> Get-ItemProperty 'HKCU:\Control Panel\Desktop' ScreenSaveActive,ScreenSaveTimeOut,ScreenSaverIsSecure" -ForegroundColor White
$Tela = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue
Write-Host "PS C:\> Get-ItemProperty 'HKLM:\...\Policies\System' InactivityTimeoutSecs" -ForegroundColor White
$GPO  = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue

$out = ([PSCustomObject]@{
    ScreenSaveActive      = if ($null -ne $Tela.ScreenSaveActive)     { $Tela.ScreenSaveActive }     else { 'AUSENTE' }
    ScreenSaveTimeOut     = if ($null -ne $Tela.ScreenSaveTimeOut)    { $Tela.ScreenSaveTimeOut }    else { 'AUSENTE' }
    ScreenSaverIsSecure   = if ($null -ne $Tela.ScreenSaverIsSecure)  { $Tela.ScreenSaverIsSecure }  else { 'AUSENTE' }
    InactivityTimeoutSecs = if ($null -ne $GPO.InactivityTimeoutSecs) { $GPO.InactivityTimeoutSecs } else { 'AUSENTE' }
} | Format-List | Out-String)
Write-Captured $out

Wait-ForScreen
Capture-Screen -FileName "10_Protecao_Tela.png"

# ==================================================================
#  11. Diretivas de Logs (Security)
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(c)" -Descricao "Diretivas de Logs (Security)"
Write-Host "PS C:\> Get-WinEvent -ListLog Security | Select-Object LogName,MaximumSizeInBytes,LogMode,IsEnabled`n" -ForegroundColor White
$out = (Get-WinEvent -ListLog Security |
        Select-Object LogName, MaximumSizeInBytes, LogMode, IsEnabled |
        Format-Table -AutoSize | Out-String)
Write-Captured $out
Wait-ForScreen
Capture-Screen -FileName "11_Diretivas_Logs.png"

# ==================================================================
#  12. Serviço de Log (Auditoria) - Parte 1
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(k)" -Descricao "Servico de Log de Eventos (EventLog) - Parte 1"
Write-Host "PS C:\> Get-Service -Name EventLog | Select-Object Name, DisplayName, Status, StartType`n" -ForegroundColor White
$out = (Get-Service -Name EventLog |
        Select-Object Name, DisplayName, Status, StartType |
        Format-Table -AutoSize | Out-String)
Write-Captured $out
Wait-ForScreen
Capture-Screen -FileName "12_Servico_EventLog_1.png"

# ==================================================================
#  13. Auditoria do Windows (auditpol)
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(k.1)" -Descricao "Auditoria do Windows (auditpol)"

$Filtro = "Extensão do sistema de segurança|Integridade do sistema|Outros Eventos do Sistema|Logon|Logon especial|Outros eventos de logon/logoff|Sistema de arquivos|Outros Eventos de Acesso a Objetos|Uso de Privilégio Não Importante|Outros Eventos de Uso de Privilégios|Uso de Privilégio Importante|Criação de processo|Terminação de processo|Auditoria de alteração de políticas|Outros eventos de alteração de política|Gerenciamento de conta de computador|Outros Eventos de Gerenciamento de Contas|Gerenciamento de conta de usuário|Acesso ao serviço de diretório|Alterações no serviço de diretório|Replicação do serviço de diretório|Replicação detalhada do serviço de diretório"

Write-Host "PS C:\> auditpol /get /category:* | Select-String -Pattern <filtro AR>`n" -ForegroundColor White
$out = (auditpol /get /category:* 2>&1 | Select-String -Pattern $Filtro | Out-String)
Write-Captured $out

Wait-ForScreen
Capture-Screen -FileName "13_Auditoria_Windows.png"

# ==================================================================
#  14. Usuários da Sessão Interativa Ativa
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(l.1)" -Descricao "Usuario da Sessao Interativa Ativa"
Write-Host "PS C:\> Get-CimInstance Win32_Process -Filter ""Name='explorer.exe'"" | Invoke-CimMethod GetOwner`n" -ForegroundColor White
$Explorer = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Explorer) {
    $Dono = Invoke-CimMethod -InputObject $Explorer -MethodName GetOwner
    Write-Host "Usuario: $($Dono.Domain)\$($Dono.User)" -ForegroundColor White
} else {
    Write-Host "Nenhuma sessao interativa (explorer.exe) encontrada." -ForegroundColor Red
}

Wait-ForScreen
Capture-Screen -FileName "14_Usuarios_Sessao.png"

# ==================================================================
#  15. Grupo de Administradores Locais
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(l.2)" -Descricao "Grupo de Administradores Locais"
Write-Host "PS C:\> Get-LocalGroupMember -SID 'S-1-5-32-544'`n" -ForegroundColor White

$out = (Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue |
        Select-Object @{Name="Origem"; Expression={$_.PrincipalSource}},
                      @{Name="Tipo"; Expression={$_.ObjectClass}},
                      @{Name="Identidade (Administrador)"; Expression={$_.Name}} |
        Format-Table -AutoSize | Out-String)
Write-Captured $out

Wait-ForScreen
Capture-Screen -FileName "15_Administradores_Locais.png"

# ==================================================================
#  Finalização da Coleta
# ==================================================================
Stop-Transcript
Clear-Host
Write-Host "=============================================" -ForegroundColor Yellow
Write-Host "COLETA FINALIZADA COM SUCESSO" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Yellow
Write-Host "`nEvidências e screenshots foram salvos em: $ScreenshotFolder" -ForegroundColor Cyan
Write-Host "Log completo (comandos + resultados) em: $logPath" -ForegroundColor Cyan
Write-Host "`nPressione qualquer tecla para sair..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")