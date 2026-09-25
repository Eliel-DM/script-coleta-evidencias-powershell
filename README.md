# Script de Coleta de Evidências — Auditoria de Conformidade (AR)

> **Versão do script:** 1.3  
> **Arquivo principal:** `index-v1.3.ps1`

## Visão Geral

Script em PowerShell desenvolvido para automatizar a coleta de evidências locais de estações de trabalho com o objetivo de **auditoria de conformidade**. Ele executa verificações em 14 categorias distintas, captura **screenshots** de cada etapa e gera um **log textual** completo, garantindo total transparência sobre os comandos executados e seus resultados.

Ideal para profissionais de segurança, TI e auditoria que precisam verificar se um computador está em conformidade com políticas de segurança corporativas — como criptografia de disco, diretivas de senha, firewall, proteção contra malware, atualizações, auditoria de logs, bloqueio de sessão, entre outros.

## Funcionalidades

- ✅ **Execução transparente** — todos os comandos são exibidos no console antes de serem executados, permitindo rastreabilidade total.
- ✅ **Captura de tela automática** — cada verificação gera um screenshot `.png` salvo na pasta de destino.
- ✅ **Log completo** — um arquivo de transcrição (.txt) registra toda a saída dos comandos para consulta posterior.
- ✅ **Independência de módulos externos** — utiliza apenas cmdlets nativos do Windows e ferramentas built-in (`manage-bde`, `net accounts`, `secedit`, `auditpol`, `w32tm`, `slmgr.vbs`, etc.).
- ✅ **Identificação da estação** — cada tela exibe hostname, número serial do BIOS, usuário logado e data/hora.
- ✅ **Tratamento de valores ausentes** — registros de registro inexistentes são exibidos como `AUSENTE` em vez de ficarem em branco.

## Verificações Realizadas

| #   | Código     | Descrição                                  | Comandos/Fontes                                                                                    |
| --- | ---------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| 1   | 4.1.1.1    | **Criptografia de disco (BitLocker)**      | `manage-bde -status`                                                                               |
| 2   | 4.1.2(b)   | **Diretivas de senha**                     | `net accounts`                                                                                     |
| 3   | 4.1.2(b.2) | **Diretiva de bloqueio de conta**          | `secedit /export` + `Select-String "Lockout"`                                                      |
| 4   | 4.1.2(d)   | **Estado do Microsoft Defender Antivírus** | `Get-MpComputerStatus`                                                                             |
| 5   | 4.1.2(e)   | **Firewall do Windows (perfis e ações)**   | `Get-NetFirewallProfile`                                                                           |
| 6   | 4.1.2(j)   | **Configuração NTP / sincronismo de hora** | `w32tm /query /configuration`, `w32tm /query /status`, `w32tm /query /source`                      |
| 7   | 4.1.2(i)   | **Acesso remoto (RDP) desabilitado**       | Registry (`fDenyTSConnections`, `PortNumber`), `Get-Service TermService`                           |
| 8   | 4.1.2(g/h) | **Especificações do Windows / Ativação**   | `Get-CimInstance Win32_OperatingSystem`, `slmgr.vbs /xpr`, `slmgr.vbs /dli`                        |
| 9   | 4.1.2(g)   | **Status do Windows Update**               | `Get-Service wuauserv` (com status/tipo em português), `Get-HotFix` (2 últimas)                    |
| 10  | 4.1.2(f)   | **Proteção de tela e bloqueio de sessão**  | Registry (`ScreenSaveActive`, `ScreenSaveTimeOut`, `ScreenSaverIsSecure`, `InactivityTimeoutSecs`) |
| 11  | 4.1.2(c)   | **Diretivas de Logs (Security)**           | `Get-WinEvent -ListLog Security`                                                                   |
| 12  | 4.1.2(k)   | **Serviço de Log de Eventos (EventLog)**   | `Get-Service EventLog`                                                                             |
| 13  | 4.1.2(k.1) | **Auditoria do Windows (auditpol)**        | `auditpol /get /category:*` com filtro específico para categorias AR                               |
| 14  | 4.1.2(l.1/l.2) | **Todos os Usuários e Níveis de Acesso**   | `Get-LocalUser`, `Get-LocalGroup`, `Get-LocalGroupMember`, `Get-CimInstance Win32_Process explorer.exe` + `GetOwner` |

## Requisitos

- **Sistema Operacional:** Windows 10/11 ou Windows Server 2016+ (compatível com PowerShell 5.1+)
- **Permissões:** Execução como **Administrador** (algumas verificações, como `auditpol` e `secedit`, exigem elevação)
- **Política de Execução:** O PowerShell deve permitir a execução de scripts. Caso necessário, execute:
  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process
  ```

## Como Utilizar

### 1. Download

Salve o arquivo `index-v1.3.ps1` no computador que será auditado.

### 2. Execução direta

Abra o PowerShell como **Administrador** e execute:

```powershell
.\index-v1.3.ps1
```

Os resultados serão salvos na pasta padrão:

```
C:\Temp\EvidenciasAR\
```

### 3. Pasta de destino personalizada

```powershell
.\index-v1.3.ps1 -ScreenshotFolder "D:\Auditoria\Evidencias"
```

### 4. Execução com bypass de política (recomendado para estações bloqueadas)

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\index-v1.3.ps1"
```

## Saída Gerada

A execução gera os seguintes arquivos na pasta de destino:

```
C:\Temp\EvidenciasAR\
├── 01_Criptografia_BitLocker.png
├── 02_Politica_Senha.png
├── 03_Diretiva_Bloqueio_Conta.png
├── 04_Antivirus.png
├── 05_Firewall.png
├── 06_Servico_NTP.png
├── 07_RDP_Desabilitado.png
├── 08_Especificacoes_Windows.png
├── 09_Windows_Update.png
├── 10_Protecao_Tela.png
├── 11_Diretivas_Logs.png
├── 12_Servico_EventLog_1.png
├── 13_Auditoria_Windows.png
├── 15_Todos_Usuarios_Acesso.png
└── Evidencias_AR_Final_yyyyMMdd_HHmmss.txt   ← log completo
```

## Fluxo de Execução

1. O script maximiza a janela do console para melhor captura de tela.
2. Para cada verificação, exibe um cabeçalho padronizado com código, descrição, hostname, serial do BIOS, usuário e data/hora.
3. Exibe o comando que será executado e imediatamente o executa.
4. Aguarda um breve intervalo para garantir que toda a saída seja capturada.
5. Captura a tela inteira e salva como PNG.
6. Ao final, para a transcrição, limpa a tela e exibe a mensagem de conclusão com o caminho dos arquivos gerados.

## Observações Técnicas

- **Transparência na auditoria:** o script foi projetado para exibir **abertamente** cada comando digitado e sua execução, eliminando qualquer suspeita de manipulação de resultados.
- **Correção de buffering (v2/v1.1):** toda saída de comando é capturada via `Out-String` e reemitida via `Write-Host`, garantindo que tanto o transcript quanto os screenshots capturem o conteúdo na ordem correta — resolvendo um problema conhecido do `Start-Transcript` com comandos nativos.
- **Aprimoramento v1.2 — Windows Update (#9):** a verificação do serviço `wuauserv` agora traduz os campos `Status` e `StartType` para português (ex.: `Running` → `Em execução`, `Automatic` → `Automático`), além de exibir nome de exibição e tipo de serviço, melhorando a legibilidade dos relatórios de auditoria.
- **Aprimoramento v1.3 — Todos os Usuários e Níveis de Acesso (#14/15):** os tópicos 14 (Usuário da sessão interativa) e 15 (Grupo de Administradores Locais) foram unificados em uma única evidência que lista **todos os usuários** (locais e externos) com seus respectivos níveis de acesso (`Administrador`, `Usuário Padrão`, `Convidado`), status da conta, grupos de pertencimento e indicação clara de quem está logado no momento (`>>> SIM <<<`).
- **Filtro auditpol:** a listagem de categorias de auditoria é filtrada estritamente para as categorias relevantes para a política AR, evitando poluição visual.
- **Valores de registro:** quando uma chave de registro não existe, o script exibe `AUSENTE` em vez de deixar o campo em branco.
- **Independência de rede:** todas as verificações são **locais**, não dependendo de conectividade com domínio ou servidores externos para sua execução.

## Histórico de Versões

| Versão | Data | Descrição                                                                                                                                                                                                                   |
| ------ | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.0    | —    | Versão inicial do script de coleta de evidências.                                                                                                                                                                           |
| 1.1    | —    | Correção de bug de buffering do `Start-Transcript`; correção do filtro do `auditpol` (Logon$ → Logon); remoção de placeholder literal do prompt; valores ausentes no registro agora exibem `AUSENTE`.                       |
| 1.2    | —    | Aprimoramento do tópico #9 (Windows Update): tradução dos campos `Status` e `StartType` do serviço `wuauserv` para português; adição de `DisplayName` e tipo de serviço na saída; atualização do prompt de comando exibido. |
| 1.3    | —    | Unificação dos tópicos #14 e #15 em uma única evidência "Todos os Usuários e Níveis de Acesso": lista todos os usuários locais e externos com nível de acesso, status, grupos e identificação do usuário logado. |

## Contribuição

Este projeto é mantido internamente e contribuições devem ser coordenadas com a equipe responsável. Para reportar problemas ou sugerir melhorias, abra uma issue no repositório.

## Licença

Uso interno — não redistribuir sem autorização.
