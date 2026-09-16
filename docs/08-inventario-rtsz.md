# 08 · Acesso ao inventário (.rtsz) sem Royal Server

> Como o MCP lê o inventário e resolve segredos lendo o documento `.rtsz` local
> do Royal TS/TSX, sem Royal Server. Premissa fechada na Decisão C.

---

## 1 · Viabilidade no macOS — confirmada

- O módulo **`RoyalDocument.PowerShell`** roda em **PowerShell Core (`pwsh`)** em
  Windows, **macOS e Linux**.
- É **grátis** (PowerShell Gallery) e **não exige Royal TS/TSX instalado nem
  licença** para manipular documentos.
- Logo: o MCP (Rust) invoca `pwsh` como subprocesso para ler/escrever o `.rtsz`.

## 2 · Formato e criptografia

- O `.rtsz` é um **XML**; dados não-sensíveis (host, porta, pasta, tags) ficam em
  texto estruturado, **dados sensíveis (senhas, campos protegidos) são sempre
  criptografados** — mesmo sem senha customizada.
- Dois modos: **Passwords-Only** (XML legível, só os segredos cifrados) e
  **Complete-File-Encryption** (arquivo inteiro cifrado).
- Para descriptografar os segredos é preciso a **senha do documento**.

## 3 · Abertura com senha

```powershell
$store = New-RoyalStore -UserName "mcp"
$pwd   = ConvertTo-SecureString $env:ROYAL_DOC_PWD -AsPlainText -Force   # NÃO hardcode
$doc   = Open-RoyalDocument -Store $store -FileName "/path/doc.rtsz" -Password $pwd
```

- A senha do documento **vem do Keychain do macOS**, nunca de env hardcoded em
  script nem de resposta de tool (igual ao princípio da seção 3 do design doc).
- `-Password` é `SecureString`; preferir `-Interactive` ou injeção via stdin a
  passar em argv.

## 4 · Implicação no threat model

O segredo é descriptografado **pelo `pwsh` (subprocesso filho do MCP)** e trafega
de volta ao processo Rust pelo canal do subprocesso. Isso está **dentro** da
fronteira de confiança do MCP, mas exige cuidado:

- Capturar o segredo num buffer **zeroizável** (`secrecy`/`zeroize`); nunca logar.
- Nunca passar segredo nem a senha do documento por **argv** (visível em `ps`) —
  usar stdin / `SecureString`.
- O `pwsh` é processo filho do MCP, não exposto ao agente.

**Reimplementar a criptografia do `.rtsz` em Rust foi descartado**: formato
proprietário, frágil a mudanças de versão, e cripto caseira é risco. `pwsh` é a
fonte de verdade.

## 5 · Estratégia de uso — somente leitura

**Premissa fechada:** o agente usa apenas hosts que já existem no Royal. O MCP
**nunca escreve no `.rtsz`** — não cria, edita nem apaga hosts/credenciais. Isso
elimina toda a armadilha de corrupção (swap atômico, lockfile, recusar com doc
aberto): só abrimos o documento em modo leitura.

| Necessidade | Como |
|---|---|
| **Inventário sem segredo** (HostView) | Ler via `pwsh` na subida, cachear em memória; recarregar por TTL ou `refresh_inventory`. Não chamar `pwsh` a cada request. |
| **Segredo (resolução de credencial)** | Resolver **lazy**, só na hora de conectar, dentro de `vault::resolve(host_id)`. Segredo nunca entra no cache do inventário nem em DTO. |
| ~~CRUD (escrita)~~ | **Fora de escopo.** Criação/edição de host é feita por você no Royal, não pelo agente. |

## 6 · Validation notes

The integration was validated locally with `pwsh` and
`RoyalDocument.PowerShell` using a private Royal document. No document,
credential, host name, address, or customer data is included in this repository.

- ✅ **Abre sem senha de documento** (modo Passwords-Only).
- ✅ **Senha sai em claro** via `.CredentialPassword` / `.EffectivePassword` —
  resolução de segredo viável sem reimplementar cripto.
- Multiple synthetic connection shapes were validated for password and key authentication
  (`EffectiveKeyContent`/`EffectiveKeyFile`). O `Vault` precisa cobrir os dois modos.
- Enumeração: `Get-RoyalObject -Store $store -Type RoyalSSHConnection` (não
  `-Folder`). Resolver credencial herdada via propriedades `Effective*`.

## 7 · Scope without tags

Royal documents do not always use tags consistently. The implementation therefore
supports exact host names and folder paths as independent scope dimensions:

- Use **folder paths** as a scope dimension when the document hierarchy already
  groups related hosts.
- Do not infer environment criticality from missing metadata. Treat every scoped
  host as sensitive infrastructure.
- Start with one synthetic or non-critical host, then expand scope deliberately.
- Hierarquia de pastas: reconstruir via `ParentID` (a propriedade `.Parent` veio
  vazia no spike).

---

## Fontes

- [RoyalDocument.PowerShell — cmdlet reference](https://docs.royalapps.com/r2021/scripting/document/cmdlet-reference/index.html)
- [PowerShell Gallery — RoyalDocument.PowerShell](https://www.powershellgallery.com/packages/RoyalDocument.PowerShell/)
- [Open-RoyalDocument](https://github.com/royalapplications/docs/blob/main/src/r2023/scripting/document/cmdlet-reference/Open-RoyalDocument.md)
- [Royal TS/TSX Encryption and Passwords](https://www.royalapps.com/blog/royal-ts-and-royal-tsx-encryption-and-passwords)
