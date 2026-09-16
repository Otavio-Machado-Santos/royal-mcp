# 09 · Modelo de conexão e escalonamento (sudo)

> Complemento ao design doc (`mcp-royal-arquitetura.html`). Cobre o transporte SSH
> até o host de destino: pool de conexões, timeouts, limites de output e a
> estratégia de privilégio. Independe de como o inventário é lido — vale tanto
> para leitura do `.rtsz` local quanto para qualquer outra fonte.
>
> Premissa fechada: **apenas Royal TS/TSX local, sem Royal Server.** O segredo é
> resolvido em memória do processo do MCP.

---

## 1 · Por que isto não é detalhe de implementação

Duas decisões aqui têm peso de threat model, não de engenharia:

1. **Como o sudo é resolvido** decide se o MCP comprometido vira root em todos os
   hosts. Se a resposta for "login direto como root via chave", você jogou fora a
   contenção de movimento lateral que o resto do doc construiu.
2. **Limite de output** é defesa contra DoS acidental *e* contra exfiltração: um
   `cat /var/log/huge` sem cap derruba o MCP; com cap + hash no log, vira evento
   auditável.

---

## 2 · Modelo de conexão (russh)

### 2.1 Pool por host, canal por comando

Handshake + auth SSH custa ~100–500 ms; abrir um *channel* numa sessão já aberta
é barato. Logo:

- **Pool**: `HashMap<HostId, PooledConn>` com conexão **preguiçosa** (conecta no
  primeiro `exec` daquele host) e **reusada** nos próximos.
- **Um canal `exec` por comando**, sobre a sessão reusada. Nunca um shell
  interativo persistente — cada comando é um `channel.exec(cmd)` isolado, captura
  `stdout`/`stderr`/`exit_status` e fecha o canal.
- **Keep-alive** (`russh` `keepalive_interval`) para segurar a sessão viva entre
  comandos sem manter tráfego.
- **Idle eviction**: fecha a sessão após N minutos ociosa (ex.: 5 min) para não
  acumular sockets nem manter a chave "viva" mais que o necessário.
- **Health check + reconnect-once**: antes de reusar, se o canal falhar (servidor
  rebootou, rede caiu), reconecta **uma vez**; se falhar de novo, erro limpo para
  o agente. Nunca loop de reconexão.

```rust
struct PooledConn {
    handle: russh::client::Handle<ClientHandler>,
    last_used: Instant,            // para idle eviction
    // sem campo de credencial — a chave já foi consumida no connect
}
```

### 2.2 Autenticação a partir do MCP (nunca do host)

- A chave privada vive em `secrecy::SecretString` / bytes com `zeroize`, carregada
  do vault **só na hora do connect**, passada ao `russh` e descartada.
- **Sem agent-forwarding** para o alvo (já no doc, seção 1): forwarding deixaria um
  host comprometido sequestrar a chave. Auth sempre originada no MCP.
- `known_hosts`: validar host key. Decisão a tomar — **TOFU** (trust-on-first-use,
  grava no primeiro contato) vs. **pinning** vindo do próprio `.rtsz` se o Royal
  guardar a fingerprint. Recusar conexão a host key mudada (possível MITM) e tratar
  como evento de auditoria, não erro silencioso.

### 2.3 Timeouts (três níveis, todos obrigatórios)

| Timeout | Default sugerido | Ação ao estourar |
|---|---|---|
| **Connect** | 10 s | aborta, erro `connect_timeout` |
| **Comando** | 30 s (configurável por chamada, teto rígido ex. 300 s) | mata o canal (`channel.eof`/`close`), retorna `timeout` + output parcial até o cap |
| **Global da request** | derivado do comando | rede do MCP não fica pendurada |

Comando de longa duração (ex.: `apt upgrade`) → exige timeout explícito na chamada,
limitado pelo teto. Sem timeout infinito.

### 2.4 Limite de output

- **Cap em bytes** por comando (ex.: 1 MiB stdout + 256 KiB stderr). Ao estourar:
  trunca, marca `truncated: true`, registra **tamanho total real + hash** no audit
  log. `file_get` (vetor de exfiltração) tem cap próprio e mais apertado.
- **Sem streaming no MVP**: tools MCP são request/response. Captura até o cap e
  devolve de uma vez. Streaming (output incremental) fica para fase posterior, se
  necessário para comandos longos.

### 2.5 Concorrência (fan-out)

- `exec` com `target = filtro` faz fan-out para N hosts. Limitar paralelismo com um
  **semáforo** (`parallel: 10` no exemplo do doc). Cada host tem sua entrada no pool.
- Resultado agregado **por host** (id → {stdout, stderr, exit, error}), nunca
  concatenado, para o agente saber exatamente onde cada coisa rodou.
- O rate-limit / circuit breaker (seção 6 do doc) conta sobre o total de canais
  abertos, não só sobre chamadas de tool.

### 2.6 PTY: não, por default

`channel.exec` sem PTY mantém `stdout`/`stderr` **separados** — essencial para
auditoria e para o agente. Pedir PTY (`request_pty`) mistura os dois e abre porta a
escape sequences. Só considerar PTY se um comando específico exigir tty (ver sudo
abaixo) — e aí isolado, não como default.

---

## 3 · Escalonamento de privilégio (sudo)

### 3.1 O que **não** fazer

- **Login direto como root** (chave root no `.rtsz`): destrói o threat model. Um
  agente que escapa do gate roda como root direto. Evitar salvo host onde root é a
  única conta (raro, e aí marcar o host inteiro como crítico).

### 3.2 Estratégia recomendada — privilégio mora no host (sudoers)

Login como **usuário não-privilegiado**; o que ele *pode* escalar é definido por
`sudoers` **no próprio host**, com `NOPASSWD` restrito a um conjunto explícito:

```sudoers
# /etc/sudoers.d/mcp-agent  (no host de destino)
mcp ALL=(root) NOPASSWD: /usr/bin/systemctl restart zabbix-agent2, \
                          /usr/bin/systemctl status *, \
                          /usr/bin/docker ps
```

**Por quê:** defense-in-depth real. Mesmo que o MCP seja comprometido, o host só
permite o que o `sudoers` lista — o limite de privilégio não depende só da política
do MCP. É a mesma filosofia da binary-allowlist, aplicada no kernel da autorização
do host.

### 3.3 Fallback — sudo com senha do vault (quando NOPASSWD não é viável)

Quando você não controla o `sudoers` do host:

- Senha de sudo é **mais um `Secret`** no vault, resolvida por host.
- Injetar via **stdin** com `sudo -S`, **nunca em argv** (argv aparece em `ps` para
  qualquer usuário do host → vazamento). Pode exigir PTY em alguns hosts; isolar
  esse caso.
- A senha trafega para a memória do processo `sudo` no host de destino. É um
  trade-off aceitável **só** quando 3.2 é impossível — e some do threat model
  "credencial nunca toca o host".

### 3.4 sudo e a política anti-catástrofe

`sudo` é tratado como wrapper. O motor localiza o binário efetivo depois das
flags, aplica a denylist de operações catastróficas e só injeta a senha quando
o comando final contém a forma esperada `sudo -S`. Pipes e composição shell
continuam permitidos; por isso o controle principal deve ser uma conta SSH de
menor privilégio e regras `sudoers` específicas no host.

---

## 4 · Estado atual

- Host keys usam TOFU persistente e falham de forma fechada se o pin não puder
  ser gravado ou se uma chave conhecida mudar.
- `sudoers` com menor privilégio continua sendo a opção recomendada; senha via
  vault é um fallback operacional.
- A saída é limitada por tamanho e timeout, sem streaming MCP.
- Aprovações de mutação de arquivo usam `elicitation` ou o modo compatível
  `agent`; execução de comandos não abre um diálogo server-side.
