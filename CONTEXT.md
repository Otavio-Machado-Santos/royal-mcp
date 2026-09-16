# Royal MCP

Fronteira de confiança entre agentes de IA e os hosts SSH dos clientes: o agente
opera hosts por nome/ID e o MCP resolve credenciais internamente, sem que
segredos cruzem para o modelo.

## Language

**Host**:
Uma conexão SSH do inventário Royal TS (`.rtsz`) que o agente pode operar. Identificado por nome exato ou ID (GUID do Royal).
_Avoid_: servidor, máquina, target

**Documento Royal**:
O arquivo `.rtsz` local, somente-leitura para o MCP, que contém o inventário de hosts e as credenciais criptografadas.
_Avoid_: banco de dados, vault file

**Vault**:
O único componente que toca segredos. Resolve a credencial de um Host por ID e a entrega ao motor SSH dentro do processo do MCP.
_Avoid_: gerenciador de senhas, credential store genérico

**Credencial Resolvida**:
O material de autenticação de um Host (usuário + senha, ou usuário + chave e passphrase) materializado em memória zeroizável, válido apenas durante a operação que o pediu.
_Avoid_: senha, segredo solto

**Fronteira de Credencial**:
A invariante central: nenhum segredo cruza para o agente, para o modelo ou para logs. Tudo que o agente recebe são IDs, nomes e resultados de operações.
_Avoid_: segurança (termo amplo demais)

**Escopo**:
O subconjunto de Hosts visível ao agente, definido no `config.toml` por nome ou pasta/cliente. Tudo fora do Escopo é negado antes de qualquer outra avaliação.
_Avoid_: permissão, allowlist

**Política Anti-Catástrofe**:
O modelo default-allow da policy: todo comando executa, exceto os catastróficos irreversíveis (formatar disco, `dd` em block device, wipe da raiz, fork bomb, desligar/reiniciar).
_Avoid_: allowlist de binários, default-deny (modelo abandonado em 2026-07)

**Aprovação**:
O gate para operações que alteram arquivos (`file_put`, `file_edit`). No modo `agent`, delegada ao agente via chat; no modo `elicitation`, diálogo MCP ao humano.
_Avoid_: confirmação, prompt

**Audit**:
O log append-only com hash-chain que registra toda operação (tool, argumentos, resultado). A "verdade de campo" do MCP.
_Avoid_: log comum, histórico
