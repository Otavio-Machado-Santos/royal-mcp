# Referência de Tools MCP

Referência completa de todas as tools expostas pelo Royal MCP.

## Tools de Leitura

### query_hosts

Lista os hosts SSH visíveis ao agente (interseção com a allowlist de escopo).

**Parâmetros:**
| Nome | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `name` | string | Não | Filtro por nome (substring; `*` como curinga) |
| `folder` | string | Não | Filtro por pasta/cliente (substring, case-insensitive) |

**Retorno:** `{ count, hosts[] }` — cada host inclui `id`, `name`, `uri`, `port`, `username`, `auth` (password/key/none), `folder`.

**Exemplo:**
```json
{"name": "query_hosts", "arguments": {"name": "zabbix"}}
```

---

### get_host

Detalhe de um único host por ID.

**Parâmetros:**
| Nome | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `id` | string | Sim | ID do host (UUID do Royal TS) |

**Retorno:** `{ host }` — o `HostView` ou `null` se não estiver no escopo.

---

### list_credentials

Lista nomes de usuário distintos dos hosts no escopo. Nunca retorna valores de credencial.

**Parâmetros:** Nenhum.

**Retorno:** `{ credentials[] }` — array de strings de username.

---

### refresh_inventory

Recarrega o inventário a partir do documento Royal TS. Use após mudanças no Royal TS.

**Parâmetros:** Nenhum.

**Retorno:** `{ status, total, visible, note }`.

---

## Tools de Execução

### exec

Executa um comando num host via SSH. Pipes (`|`), redireção (`>`), encadeamento
(`;`, `&&`), interpretadores (`bash -c`, `python3`) e `sudo` são permitidos —
`sudo` usa a senha do vault injetada no stdin do canal (`sudo -S`), sem expô-la.

**Parâmetros:**
| Nome | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `host` | string | Sim | Nome ou ID do host (precisa estar no escopo) |
| `command` | string | Sim | Comando a executar (composição de shell permitida) |

**Retorno:** `{ status, exit_code, stdout, stderr, truncated, note }`.

**Política (default-allow anti-catástrofe):** todo comando executa, exceto os
catastróficos irreversíveis — formatar disco (`mkfs`, `fdisk`, `parted`,
`wipefs`, `blkdiscard`), `dd`/`shred`, escrita em block device, wipe da raiz
(`rm -rf /` e dirs críticos), fork bomb, desligar/reiniciar (`shutdown`,
`reboot`, `halt`, `poweroff`, `init`).

**Negado imediatamente (antes do SSH):**
- Host fora do escopo
- Rate limit excedido
- Comando catastrófico (denylist)

---

### health_check

Roda um runbook diagnóstico fixo num host. Executa: `hostname`, `uptime`, `df -h`.

**Parâmetros:**
| Nome | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `host` | string | Sim | Nome ou ID do host (precisa estar no escopo) |

**Retorno:** `{ status, host, items[], note }` — cada item tem `command`, `exit_code`, `stdout`, `stderr`.

---

## Operações de Arquivo

### file_get

Lê um arquivo de um host via SFTP.

**Parâmetros:**
| Nome | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `host` | string | Sim | Nome ou ID do host (precisa estar no escopo) |
| `path` | string | Sim | Caminho absoluto do arquivo remoto |

**Retorno:** `{ status, path, size, sha256, truncated, content, note }`.

**Paths bloqueados:** `/etc/shadow`, chaves SSH, `.pem`/`.key`/`.ppk`/`.pfx`, `authorized_keys`, `sudoers`, `/proc/kcore`, `/dev/mem`, e outros configurados em `config.toml`.

---

### file_put

Grava um arquivo num host via SFTP, com três modos (ADR-0004):

| Modo | Comportamento |
|---|---|
| `create` (default) | Só cria arquivo **novo**; falha se o path já existir (`O_EXCL`) |
| `overwrite` | Sobrescreve (trunca) arquivo existente. Exige aprovação |
| `append` | Anexa ao final do arquivo. Exige aprovação |

**Parâmetros:**
| Nome | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `host` | string | Sim | Nome ou ID do host (precisa estar no escopo) |
| `path` | string | Sim | Caminho absoluto do arquivo remoto |
| `content` | string | Um dos dois | Conteúdo texto a gravar |
| `content_b64` | string | Um dos dois | Conteúdo em base64 — para arquivos **binários** |
| `mode` | string | Não | `create` (default), `overwrite` ou `append` |

**Retorno:** `{ status, path, bytes, note }`.

**Exige aprovação humana** (todos os modos). Denylist de paths e cap de tamanho
(`max_put_bytes`) se aplicam — acima do cap, use o upload em chunks.

---

### upload_start / upload_chunk / upload_finish / upload_abort

Upload em chunks para arquivos grandes, com verificação de integridade
(ADR-0004). O destino final **só é tocado no finish**, após o sha256 conferir.

1. `upload_start { host, path, mode? }` → cria um temporário no host e devolve
   `{ upload_id }`. Exige aprovação humana.
2. `upload_chunk { upload_id, content_b64 }` → anexa o chunk; devolve
   `{ bytes_total, chunk_sha256 }` (sha de cada chunk no audit).
3. `upload_finish { upload_id, expected_sha256 }` → verifica o sha256 do
   arquivo completo; conferindo, move para o destino no modo escolhido
   (`create` falha se o destino existir; `overwrite` substitui; `append` anexa).
   Se o hash **não** conferir: destino intocado, temporário removido.
4. `upload_abort { upload_id }` → descarta o upload e remove o temporário.

---

### file_edit

Edita um arquivo **existente** substituindo exatamente uma ocorrência de um texto.

**Parâmetros:**
| Nome | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `host` | string | Sim | Nome ou ID do host (precisa estar no escopo) |
| `path` | string | Sim | Caminho absoluto do arquivo existente |
| `old_string` | string | Sim | Texto exato a localizar (deve ocorrer exatamente uma vez) |
| `new_string` | string | Sim | Texto de substituição |

**Retorno:** `{ status, path, bytes, note }`.

**Exige aprovação humana.** O servidor:
1. Lê o arquivo e valida a substituição
2. Pede aprovação humana (mostrando host, path, mudança de tamanho)
3. Relê e verifica SHA-256 (proteção TOCTOU)
4. Grava o conteúdo atualizado

**Negado se:**
- `old_string` não encontrado ou encontrado mais de uma vez (ambíguo)
- Arquivo excede o cap de leitura
- Arquivo não é UTF-8
- Arquivo mudou entre a aprovação e a gravação
