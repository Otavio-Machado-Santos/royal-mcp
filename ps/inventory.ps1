# Emite o inventário de conexões SSH do documento Royal como JSON.
# NUNCA emite segredos — apenas metadados e flags has_password/has_key.
# Inclui o caminho da pasta (folder) reconstruído via ParentID.
# Uso: pwsh -NoProfile -File ps/inventory.ps1 -DocPath /caminho/Connections.rtsz
param(
    [Parameter(Mandatory = $true)][string]$DocPath
)
$ErrorActionPreference = 'Stop'
Import-Module RoyalDocument.PowerShell

$store = New-RoyalStore -UserName "royal-mcp"
$doc   = Open-RoyalDocument -Store $store -FileName $DocPath

# Mapa de pastas: ID -> [pscustomobject]{ Name, ParentID } para montar o caminho.
$folders = @{}
foreach ($f in @(Get-RoyalObject -Store $store -Type RoyalFolder)) {
    $par = ''
    try { $par = [string]$f.ParentID } catch {}
    $folders[[string]$f.ID] = [pscustomobject]@{ Name = [string]$f.Name; ParentID = $par }
}

# Resolve o caminho "A/B/C" subindo pelos ParentID. Guarda contra ciclos.
function Resolve-FolderPath([string]$startId) {
    $parts = New-Object System.Collections.Generic.List[string]
    $cur = $startId
    $guard = 0
    # $script:folders torna a dependência de escopo explícita (não herança implícita).
    while ($cur -and $script:folders.ContainsKey($cur) -and $guard -lt 64) {
        $node = $script:folders[$cur]
        if ($node.Name) { $parts.Insert(0, $node.Name) }
        $cur = $node.ParentID
        $guard++
    }
    return ($parts -join '/')
}

$ssh = @(Get-RoyalObject -Store $store -Type RoyalSSHConnection)

$out = foreach ($c in $ssh) {
    $uri = ([string]$c.URI).Trim()
    if ($uri -eq '') { continue }   # pula templates sem URI

    $hasPwd = $false; $hasKey = $false
    try { if ($c.EffectivePassword) { $hasPwd = $true } } catch {}
    try { if ($c.EffectiveKeyContent -or $c.EffectiveKeyFile) { $hasKey = $true } } catch {}

    $parentId = ''
    try { $parentId = [string]$c.ParentID } catch {}
    $folder = Resolve-FolderPath $parentId

    [pscustomobject]@{
        id           = [string]$c.ID
        name         = [string]$c.Name
        uri          = $uri
        port         = [int]$c.Port
        username     = [string]$c.CredentialUsername
        has_password = $hasPwd
        has_key      = $hasKey
        folder       = $folder
    }
}

# -AsArray garante um array JSON mesmo com 0 ou 1 elemento (PowerShell 7+).
$out | ConvertTo-Json -Depth 4 -AsArray
