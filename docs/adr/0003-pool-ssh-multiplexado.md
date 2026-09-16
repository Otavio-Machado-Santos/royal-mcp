# ADR-0003 — Pool SSH: uma conexão multiplexada por host

Contexto: conexão efêmera por operação causou timeouts recorrentes no audit
(concentrados em rajadas) e 1-3s de handshake por comando. O padrão de uso real
é de rajadas sequenciais no mesmo host (deploys, diagnósticos) e fan-out
paralelo entre hosts distintos.

Decisão: uma conexão SSH por host, com canais multiplexados (russh channels).
Cada operação abre um canal na conexão quente do host. Expira após ~60-90s
idle; conexão morta é reconectada transparentemente uma vez com backoff de ~2s
antes de declarar erro. Um semáforo de ~8 canais concorrentes por host respeita
o `MaxSessions` default do OpenSSH (10). Pinning de host key segue por conexão
(TOFU persistente, inalterado); `sudo -S` segue por canal (stdin do canal),
inalterado.

Alternativas consideradas: pool clássico de 2-4 conexões por host — rejeitado
porque o fan-out real é entre hosts, não dentro de um, e o custo de lifecycle
não se paga abaixo de ~10 operações simultâneas no mesmo host; manter efêmero
com retry — resolve metade dos timeouts mas preserva o custo de handshake por
comando para sempre.
