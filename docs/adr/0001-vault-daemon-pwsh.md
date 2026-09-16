# ADR-0001 — Resolução de credencial via daemon pwsh persistente

Contexto: o modelo "um `pwsh` frio por operação" (`vault.rs` + `resolve.ps1`)
causou falhas repetidas de resolução no audit (lock do `.rtsz` com o Royal TS aberto,
contenção em rajadas, stdout parcial) e latência de 1-3s por comando — motivo
histórico de contorno do MCP por scripts próprios.

Decisão: o vault passa a ser um **daemon PowerShell de longa duração**, filho do
processo do MCP, que abre o documento Royal uma vez e atende pedidos de
resolução de credencial por `host_id` via stdin/stdout (JSON por linha). O
segredo continua trafegando apenas do daemon para o processo do MCP — nunca
para o agente nem para logs.

Alternativas consideradas: (A) cópia do `.rtsz` para temp + cache por host —
menor delta, mas mantém o cold-start por cache-miss e a fragilidade do spawn
por operação; (C) preload de todas as credenciais em memória no boot —
descartada por quebrar a invariante de resolver apenas o necessário e manter
todos os segredos do documento residentes no processo.

Consequências: medições locais mostraram memória estável e CPU ociosa — mais
barato que o modelo de spawn por operação em sessões de trabalho reais. O daemon precisa de
supervisão (restart em morte) e de uma estratégia de invalidação do documento
(ver ADR-0002 quando decidida).
