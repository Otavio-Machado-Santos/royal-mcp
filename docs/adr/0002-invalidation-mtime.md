# ADR-0002 — Invalidação do Documento Royal por mtime, com hook no refresh_inventory

Contexto: com o daemon pwsh (ADR-0001), o documento fica aberto em memória e
pode ficar desatualizado quando o dono edita o Royal TS (host novo, senha
rotacionada). O modelo anterior reabria o arquivo a cada operação, então
staleness não existia.

Decisão: o daemon faz `stat` do `.rtsz` antes de cada resolução; se o mtime
mudou, fecha e reabre o documento. A tool `refresh_inventory` passa a também
forçar a reabertura no daemon (antes só recarregava o inventário em memória do
Rust). Na janela em que o Royal TS está salvando (arquivo travado), o daemon
faz 2-3 retries de ~500ms e, persistindo a falha, atende com o documento
anterior sinalizando o aviso.

Alternativas consideradas: reload apenas via `refresh_inventory` — rejeitada
porque a tool é raramente chamada (44 usos em 3 meses contra 5.471 `exec`), o
que deixaria senhas rotacionadas invisíveis; TTL fixo — rejeitado por manter
janela de staleness e reabrir sem necessidade.
