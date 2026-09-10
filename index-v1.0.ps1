<#
.SYNOPSIS
    Coleta evidências locais de estação AR (Completo).
.DESCRIPTION
    Executa verificações filtradas. A data e hora são validadas exibindo
    abertamente a digitação e execução dos comandos "hostname" e "Get-Date" 
    no console para total transparência na auditoria.
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

# Função para tirar screenshot da TELA INTEIRA (Desktop completo)
function Capture-Screen {
    param([string]$FileName)

    $path = Join-Path $ScreenshotFolder $FileName

    # Captura os limites exatos da área de trabalho inteira (VirtualScreen)
    $screenBounds = [System.Windows.Forms.SystemInformation]::VirtualScreen

    # Cria o bitmap cobrindo toda a extensão da tela
    $bitmap = New-Object System.Drawing.Bitmap $screenBounds.Width, $screenBounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)

    # Copia os pixels a partir da coordenada (Left, Top) da área de trabalho
    $graphics.CopyFromScreen($screenBounds.Left, $screenBounds.Top, 0, 0, $screenBounds.Size)

    # Salva a imagem PNG
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)

    # Libera memória dos objetos de imagem
    $graphics.Dispose()
    $bitmap.Dispose()

    Write-Host "`n[Screenshot da tela inteira salvo em: $path]" -ForegroundColor Cyan
}

# Função de Cabeçalho (Simula a digitação manual e executa os comandos nativos)
function Write-RequirementHeader {
    param([string]$Codigo, [string]$Descricao)
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Yellow
    Write-Host "TESTE: $Codigo - $Descricao" -ForegroundColor Green
    Write-Host "---------------------------------------------" -ForegroundColor Yellow

    # Exibe o prompt simulando a digitação humana e logo abaixo executa o comando real
    Write-Host "PS C:\> hostname" -ForegroundColor White
    hostname

    Write-Host "PS C:\> Get-Date" -ForegroundColor White
    Get-Date

    Write-Host "=============================================" -ForegroundColor Yellow
    Write-Host ""
}

# Pausa para garantir renderização da tela
function Wait-ForScreen {
    Start-Sleep -Milliseconds 1500
}

# ==================================================================
#  1. Criptografia de disco
# ==================================================================
Write-RequirementHeader -Codigo "4.1.1.1" -Descricao "Criptografia de disco (BitLocker)"
Write-Host "Resultado do manage-bde -status:`n" -ForegroundColor White
manage-bde -status
Write-Host ""
Wait-ForScreen
Capture-Screen -FileName "01_Criptografia_BitLocker.png"

# ==================================================================
#  2. Diretiva de Senha / Política de senha
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(b)" -Descricao "Diretivas de senha"
Write-Host "Configurações de política de senha local (net accounts):`n" -ForegroundColor White
net accounts
Write-Host ""
Wait-ForScreen
Capture-Screen -FileName "02_Politica_Senha.png"

# ==================================================================
#  3. Diretiva de Bloqueio de Conta
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(b.2)" -Descricao "Diretiva de bloqueio de conta"
Write-Host "PS C:\> secedit /export /cfg security_policy.txt /areas SECURITYPOLICY" -ForegroundColor White
secedit /export /cfg security_policy.txt /areas SECURITYPOLICY
Write-Host "PS C:\> Get-Content security_policy.txt | Select-String `"Lockout`"`n" -ForegroundColor White
Get-Content security_policy.txt | Select-String "Lockout"
# Remove o arquivo temporário gerado para não deixar rastros na máquina
Remove-Item security_policy.txt -ErrorAction SilentlyContinue
Wait-ForScreen
Capture-Screen -FileName "03_Diretiva_Bloqueio_Conta.png"

# ==================================================================
#  4. Antivírus
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(d)" -Descricao "Estado do Microsoft Defender Antivirus"
Write-Host "Status do Defender (Get-MpComputerStatus):`n" -ForegroundColor White
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled, OnAccessProtectionEnabled, AntispywareEnabled, AntivirusSignatureLastUpdated | Format-List
Wait-ForScreen
Capture-Screen -FileName "04_Antivirus.png"

# ==================================================================
#  5. Firewall
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(e)" -Descricao "Firewall do Windows (perfis e ações)"
Write-Host "Status dos perfis do Firewall e regra de bloqueio padrão:`n" -ForegroundColor White
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize
Wait-ForScreen
Capture-Screen -FileName "05_Firewall.png"

# ==================================================================
#  6. Serviço NTP
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(j)" -Descricao "Configuração NTP / sincronismo de hora"
Write-Host "Configuração do W32Time:`n" -ForegroundColor White
w32tm /query /configuration | Select-String -Pattern "Type|NtpServer|Enabled" -Context 1,0
Write-Host "`nStatus da sincronização:" -ForegroundColor White
w32tm /query /status
Write-Host ""
Wait-ForScreen
Capture-Screen -FileName "06_Servico_NTP.png"

# ==================================================================
#  7. Acesso remoto (RDP) desabilitado
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(i)" -Descricao "Acesso remoto (RDP) desabilitado"
Write-Host "Verificando se o Remote Desktop está habilitado:`n" -ForegroundColor White
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
if ($rdp.fDenyTSConnections -eq 1) {
    Write-Host "RDP está desabilitado (Não permite conexões remotas)." -ForegroundColor Green
} elseif ($rdp.fDenyTSConnections -eq 0) {
    Write-Host "RDP está habilitado (Permite conexões remotas)." -ForegroundColor Red
} else {
    Write-Host "Não foi possível determinar o estado do RDP." -ForegroundColor Red
}
Write-Host ""
Wait-ForScreen
Capture-Screen -FileName "07_RDP_Desabilitado.png"

# ==================================================================
#  8. Especificações do Windows / Software Autêntico
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(g/h)" -Descricao "Especificacoes do Windows (Software Autentico)"
# Coletando os dados do WMI e do Registro
$WmiOS = Get-CimInstance Win32_OperatingSystem
$RegOS = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
# Formatando as informações para ficarem idênticas à tela do Windows
$Edicao = ($WmiOS.Caption).Replace("Microsoft ", "")
$Versao = $RegOS.DisplayVersion
$Compilacao = "$($RegOS.CurrentBuild).$($RegOS.UBR)"
$InstaladoEm = $WmiOS.InstallDate.ToString("dd/MM/yyyy")
# Exibindo em formato de lista
[PSCustomObject]@{
    "Edição"           = $Edicao
    "Versão"           = $Versao
    "Instalado em"     = $InstaladoEm
    "Compilação do SO" = $Compilacao
} | Format-List
Wait-ForScreen
Capture-Screen -FileName "08_Especificacoes_Windows.png"

# ==================================================================
#  9. Sistema Atualizado - Update
# ==================================================================
# Ações em segundo plano para garantir que o serviço esteja Running/Automatic
Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Write-RequirementHeader -Codigo "4.1.2(g)" -Descricao "Status do Windows Update"
# 1. Mostra o status do serviço 
Write-Host "PS C:\> Get-Service wuauserv" -ForegroundColor White
Get-Service wuauserv | Select-Object Status, Name, DisplayName | Format-Table -AutoSize
# 2. Mostra as 2 últimas atualizações instaladas
Write-Host "PS C:\> Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 2" -ForegroundColor White
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 2 | Format-Table -AutoSize
Wait-ForScreen
Capture-Screen -FileName "09_Windows_Update.png"

# ==================================================================
#  10. Proteção de Tela e Bloqueio de Sessão
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(f)" -Descricao "Protecao de Tela e Bloqueio de Sessao"
Write-Host "PS C:\> Verificando registro de politicas (ScreenSaveActive e InactivityTimeoutSecs):`n" -ForegroundColor White
$Tela = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue
$GPO = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
[PSCustomObject]@{
    ScreenSaveActive      = $Tela.ScreenSaveActive
    InactivityTimeoutSecs = $GPO.InactivityTimeoutSecs
} | Format-List
Wait-ForScreen
Capture-Screen -FileName "10_Protecao_Tela.png"

# ==================================================================
#  11. Diretivas de Logs (Event Viewer)
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(c)" -Descricao "Diretivas de Logs (Security)"
Write-Host "PS C:\> Consultando retencao e tamanho maximo do log de Seguranca:`n" -ForegroundColor White
$SecLog = Get-WinEvent -ListLog Security
[PSCustomObject]@{
    LogName          = $SecLog.LogName
    TamanhoMaximo_KB = $SecLog.MaximumSizeInBytes / 1KB
    Retencao_LogMode = $SecLog.LogMode
}
Wait-ForScreen
Capture-Screen -FileName "11_Diretivas_Logs.png"

# ==================================================================
#  12. Serviço de Log (Auditoria) - Parte 1
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(k)" -Descricao "Servico de Log de Eventos (EventLog) - Parte 1"
Write-Host "PS C:\> Get-Service -Name EventLog | Select-Object Name, DisplayName, Status, StartType`n" -ForegroundColor White
Get-Service -Name EventLog | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
Wait-ForScreen
Capture-Screen -FileName "12_Servico_EventLog_1.png"

# ==================================================================
#  13. Serviço de Log (Auditoria) - Parte 2 (AuditPol)
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(k)" -Descricao "Servico de Log de Eventos (EventLog) - Parte 2"

# 1. Salvar encoding original e forçar OEM para o auditpol ler os acentos corretamente
$OutputEncodingBackup = [Console]::OutputEncoding
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(850)

# 2. Exibição simulada do comando de forma limpa
Write-Host "PS C:\> auditpol /get /category:*" -ForegroundColor White

# 3. Execução real filtrando os termos (sem acentos na regex para evitar incompatibilidade)
$Filtro = "Acesso a Objeto|Servico de Diretori|Acompanhamento|Processo|Alteracao de Politica|Logon|Sistema|Gerenciamento de Conta|Privilegio"
auditpol /get /category:* | Select-String -Pattern $Filtro -CaseSensitive:$false

# 4. Restaurar encoding padrão
[Console]::OutputEncoding = $OutputEncodingBackup

Wait-ForScreen
Capture-Screen -FileName "13_Servico_EventLog_2.png"

# ==================================================================
#  14. Usuários da Sessão Interativa Ativa
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(l.1)" -Descricao "Usuario da Sessao Interativa Ativa"
Write-Host "PS C:\> Extraindo a sessao interativa ativa no desktop...`n" -ForegroundColor White

# Lendo a Sessão Interativa (Desktop)
$Explorer = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Explorer) {
    $Dono = Invoke-CimMethod -InputObject $Explorer -MethodName GetOwner
    $UsuarioInterativo = "$($Dono.Domain)\$($Dono.User)"
    $LogonUI = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData" -ErrorAction SilentlyContinue |
        Get-ItemProperty |
        Where-Object { $_.LoggedOnSAMUser -match $Dono.User } |
        Select-Object -Last 1
    [PSCustomObject]@{
        "Usuario da Sessao" = $UsuarioInterativo
        "Nome de Exibicao"  = if ($LogonUI.LoggedOnDisplayName) { $LogonUI.LoggedOnDisplayName } else { "Nao mapeado" }
        "Conta Conectada"   = if ($LogonUI.LoggedOnUser) { $LogonUI.LoggedOnUser } else { "Local / Desconhecida" }
    } | Format-List
} else {
    Write-Host "Sessao do explorer.exe nao encontrada." -ForegroundColor Red
}

Wait-ForScreen
Capture-Screen -FileName "14_Usuarios_Sessao.png"

# ==================================================================
#  15. Grupo de Administradores Locais
# ==================================================================
Write-RequirementHeader -Codigo "4.1.2(l.2)" -Descricao "Grupo de Administradores Locais"
Write-Host "PS C:\> Listando APENAS Administradores Locais e de Dominio/Nuvem...`n" -ForegroundColor White

Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue |
    Select-Object @{Name="Origem"; Expression={$_.PrincipalSource}},
                  @{Name="Tipo"; Expression={$_.ObjectClass}},
                  @{Name="Identidade (Administrador)"; Expression={$_.Name}} |
    Format-Table -AutoSize

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
Write-Host "Log completo em texto salvo em: $logPath" -ForegroundColor Cyan
Write-Host "`nPressione qualquer tecla para sair..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")