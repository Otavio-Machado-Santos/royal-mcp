# ADR-0004 — file_put com mode (create/overwrite/append) + binário em chunks

Contexto: a regra de ouro fundadora "não sobrescrever — só criar" (`O_EXCL`)
mostrou-se inócua na prática: 20+ sessões de chat registram deploys feitos por
fora do MCP via `exec` + `python3 base64.b64decode(...)`, sem audit de arquivo,
sem sha256 e com quoting frágil. O audit acumula erros `file_put ... (já
existe?)` de agentes tropeçando no create-only em retries de deploy.

Decisão: `file_put` ganha `mode`: `create` (default, comportamento atual),
`overwrite` (sob o gate de Aprovação, como `file_edit`) e `append`. Aceita
`content_b64` para binário. Arquivos grandes sobem em chunks nativos
(`upload_start`/`upload_chunk`/`upload_finish`), com sha256 de cada chunk e do
arquivo final registrados no Audit. O default `create` preserva a proteção
anti-acidente para quem não pede explicitamente outra coisa.

Alternativas consideradas: tool separada `file_overwrite` — rejeitada por
duplicar superfície quase idêntica (os chats mostram o modelo confundindo tools
parecidas); não mexer — rejeitado porque o contorno via exec continuaria sendo
o padrão de deploy, porém fora do Audit.

Consequências: a regra de ouro original (era default-deny) é formalmente
substituída por "create por default, overwrite sob Aprovação" — coerente com a
filosofia anti-acidente vigente desde 2026-07-02. Deploys passam a acontecer
dentro do Audit.
