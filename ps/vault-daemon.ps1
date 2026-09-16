# Daemon do Vault (ADR-0001/0002): processo pwsh de longa duração, filho do MCP.
# Abre o documento Royal UMA vez e atende pedidos por stdin/stdout, um JSON por
# linha. Segredos trafegam APENAS deste processo para o processo do MCP — nunca
# para o agente nem para logs.
#
# Protocolo (uma linha JSON por mensagem):
#   → {"cmd":"ping"}                      ← {"ok":true}
#   → {"cmd":"reload"}                    ← {"ok":true,"hosts":N} | {"ok":false,"error":"..."}
#   → {"cmd":"resolve","host_id":"..."}   ← {username,auth,password,key_content,passphrase,stale}
#                                           | {"error":"..."}
# Na partida emite: {"ready":true,"hosts":N} | {"ready":false,"error":"..."}
#
# Invalidação (ADR-0002): antes de cada resolve compara o LastWriteTimeUtc do
# .rtsz com o do documento aberto; mudou → reabre (3 tentativas, 500ms). Se o
# Royal TS estiver salvando (lock), atende com o documento anterior + stale=true.
param(
    [Parameter(Mandatory = $true)][string]$DocPath
)
$ErrorActionPreference = 'Stop'
Import-Module RoyalDocument.PowerShell

$script:store = $null
$script:doc = $null
$script:mtime = $null

function Open-Doc {
    # Abre (ou reabre) o documento e registra o mtime da abertura.
    $script:store = New-RoyalStore -UserName "royal-mcp-daemon"
    $script:doc = Open-RoyalDocument -Store $script:store -FileName $DocPath
    $script:mtime = (Get-Item -LiteralPath $DocPath).LastWriteTimeUtc
}

function Ensure-Fresh {
    # Retorna $true se está atendendo com documento STALE (reabertura falhou).
    $current = (Get-Item -LiteralPath $DocPath).LastWriteTimeUtc
    if ($null -eq $script:doc) { Open-Doc; return $false }
    if ($current -ne $script:mtime) {
        $attempts = 0
        while ($attempts -lt 3) {
            try { Open-Doc; return $false } catch { $attempts++; Start-Sleep -Milliseconds 500 }
        }
        return $true
    }
    return $false
}

function Resolve-Host([string]$HostId) {
    $ssh = @(Get-RoyalObject -Store $script:store -Type RoyalSSHConnection)
    $c = $ssh | Where-Object { [string]$_.ID -eq $HostId } | Select-Object -First 1
    if (-not $c) { throw "host nao encontrado: $HostId" }

    # Effective* resolvem credencial herdada/por referência (mesma lógica do
    # antigo resolve.ps1 — comportamento idêntico por contrato).
    $pwd = $null; $key = $null; $pass = $null
    try { $pwd  = [string]$c.EffectivePassword } catch {}
    try { $key  = [string]$c.EffectiveKeyContent } catch {}
    try { $pass = [string]$c.EffectivePassphrase } catch {}

    # Royal pode apontar chave por arquivo (EffectiveKeyFile) sem KeyContent.
    if (-not $key) {
        try {
            $keyFile = [string]$c.EffectiveKeyFile
            if ($keyFile) {
                $expanded = [Environment]::ExpandEnvironmentVariables(($keyFile -replace '^~', $HOME))
                if (Test-Path -LiteralPath $expanded) { $key = [IO.File]::ReadAllText($expanded) }
            }
        } catch {}
    }

    if ($key -eq "0") { $key = "" }
    $auth = if ($key -and $key.Trim() -ne "") { 'key' } elseif ($pwd) { 'password' } else { 'none' }

    return @{
        username    = [string]$c.EffectiveUsername
        auth        = $auth
        password    = $pwd
        key_content = $key
        passphrase  = $pass
    }
}

function Write-Resp($obj) {
    [Console]::Out.WriteLine(($obj | ConvertTo-Json -Compress -Depth 4))
    [Console]::Out.Flush()
}

# ---- partida: abre o documento e avisa prontidão ----
try {
    Open-Doc
    $n = @(Get-RoyalObject -Store $script:store -Type RoyalSSHConnection).Count
    Write-Resp @{ ready = $true; hosts = $n }
} catch {
    Write-Resp @{ ready = $false; error = [string]$_.Exception.Message }
}

# ---- loop principal ----
while ($true) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line) { break }  # stdin fechado (MCP morrendo) → sai
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $resp = $null
    try {
        $req = $line | ConvertFrom-Json
        switch ($req.cmd) {
            'ping' {
                $resp = @{ ok = $true }
            }
            'reload' {
                $attempts = 0; $done = $false; $err = $null
                while ($attempts -lt 3 -and -not $done) {
                    try { Open-Doc; $done = $true } catch { $attempts++; $err = $_.Exception.Message; Start-Sleep -Milliseconds 500 }
                }
                if ($done) {
                    $n = @(Get-RoyalObject -Store $script:store -Type RoyalSSHConnection).Count
                    $resp = @{ ok = $true; hosts = $n }
                } else {
                    $resp = @{ ok = $false; error = [string]$err }
                }
            }
            'resolve' {
                $stale = Ensure-Fresh
                $cred = Resolve-Host ([string]$req.host_id)
                $cred['stale'] = $stale
                $resp = $cred
            }
            default {
                $resp = @{ error = "cmd desconhecido: $($req.cmd)" }
            }
        }
    } catch {
        $resp = @{ error = [string]$_.Exception.Message }
    }
    Write-Resp $resp
}
