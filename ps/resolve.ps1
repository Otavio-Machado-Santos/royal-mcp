# Resolve a credencial de UM host (por ID) e emite JSON com o segredo.
# Este é o ÚNICO script que emite segredo no stdout — capturado pelo processo
# Rust como `Secret`, nunca logado. Subprocesso filho do MCP, fora do agente.
# Uso: pwsh -NoProfile -File ps/resolve.ps1 -DocPath <doc> -HostId <guid>
param(
    [Parameter(Mandatory = $true)][string]$DocPath,
    [Parameter(Mandatory = $true)][string]$HostId
)
$ErrorActionPreference = 'Stop'
Import-Module RoyalDocument.PowerShell

$store = New-RoyalStore -UserName "royal-mcp"
$doc   = Open-RoyalDocument -Store $store -FileName $DocPath

$ssh = @(Get-RoyalObject -Store $store -Type RoyalSSHConnection)
$c = $ssh | Where-Object { [string]$_.ID -eq $HostId } | Select-Object -First 1
if (-not $c) { Write-Error "host nao encontrado: $HostId"; exit 2 }

# Usa as propriedades Effective* (resolvem credencial herdada/por referência).
$pwd = $null; $key = $null; $pass = $null
try { $pwd  = [string]$c.EffectivePassword } catch {}
try { $key  = [string]$c.EffectiveKeyContent } catch {}
try { $pass = [string]$c.EffectivePassphrase } catch {}

# Royal pode apontar chave por arquivo (EffectiveKeyFile) sem preencher KeyContent.
if (-not $key) {
    try {
        $keyFile = [string]$c.EffectiveKeyFile
        if ($keyFile) {
            $expanded = [Environment]::ExpandEnvironmentVariables(
                ($keyFile -replace '^~', $HOME)
            )
            if (Test-Path -LiteralPath $expanded) {
                $key = [IO.File]::ReadAllText($expanded)
            }
        }
    } catch {}
}

if ($key -eq "0") { $key = "" }
$auth = if ($key -and $key.Trim() -ne "") { 'key' } elseif ($pwd) { 'password' } else { 'none' }


[pscustomobject]@{
    username    = [string]$c.EffectiveUsername
    auth        = $auth
    password    = $pwd
    key_content = $key
    passphrase  = $pass
} | ConvertTo-Json -Depth 3 -Compress
