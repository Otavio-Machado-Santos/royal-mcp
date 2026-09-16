//! Servidor MCP. Tools de leitura (`query_hosts`, `get_host`, `list_credentials`,
//! `refresh_inventory`), execução (`exec`, `health_check`) e arquivos
//! (`file_get`, `file_put` com modes, `file_edit`, upload em chunks).
//! Nenhuma retorna credencial.
//!
//! Fluxo das tools mutáveis:
//!   escopo de host → rate-limit → política/denylist → (mutação) APROVAÇÃO →
//!   resolução de credencial (vault daemon) → SSH/SFTP (pool multiplexado) →
//!   audit (hash-chain).
//! A política de exec só bloqueia comandos catastróficos irreversíveis
//! (default-allow, ver `policy.rs`). Em modo headless sem elicitation, use
//! `approval_mode = "agent"` para delegar a aprovação ao agente.
//!
//! Nota: a spec do MCP exige `outputSchema` com root `object` — cada retorno é
//! envelopado num struct.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::{Peer, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::AuditLog;
use crate::config::{ApprovalMode, Config};
use crate::inventory::Inventory;
use crate::model::HostView;
use crate::policy::{self, Decision};
use crate::ratelimit::RateLimiter;
use crate::ssh::{self, SshPool, WriteMode};
use crate::vault::{self, AuthMaterial, ResolvedCredential};

/// Senha usável para `sudo -S` (só quando o host autentica por senha). Fica
/// dentro do processo do MCP; nunca é logada nem retornada ao agente.
fn sudo_password(cred: &ResolvedCredential) -> Option<&str> {
    match &cred.auth {
        AuthMaterial::Password(s) => Some(s.expose()),
        _ => None,
    }
}

/// Estado de um upload em chunks em andamento (ADR-0004). O destino final só é
/// tocado no `upload_finish`, após verificação de sha256.
struct UploadState {
    host_id: String,
    uri: String,
    port: u16,
    dest: String,
    temp_path: String,
    mode: WriteMode,
    bytes: usize,
}

struct Inner {
    inv: RwLock<Inventory>,
    audit: AuditLog,
    cfg: Config,
    pool: SshPool,
    limiter: RateLimiter,
    uploads: Mutex<HashMap<String, UploadState>>,
}

#[derive(Clone)]
pub struct RoyalServer {
    inner: Arc<Inner>,
}

/// Formulário de aprovação renderizado pelo harness (fora do contexto do LLM).
#[derive(Debug, Deserialize, JsonSchema)]
struct ApprovalForm {
    /// Marque para APROVAR esta operação que altera estado num host de produção.
    approved: bool,
}
rmcp::elicit_safe!(ApprovalForm);

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryHostsArgs {
    /// Filtro por nome (substring; `*` como curinga). Vazio/ausente = todos no escopo.
    #[serde(default)]
    pub name: Option<String>,
    /// Filtro por pasta/cliente (substring, case-insensitive).
    #[serde(default)]
    pub folder: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetHostArgs {
    /// ID do host.
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecArgs {
    /// Host alvo: nome exato ou ID. Precisa estar no escopo permitido.
    pub host: String,
    /// Comando a executar. Pipes (`|`), redireção (`>`), encadeamento (`;`, `&&`),
    /// interpretadores (`bash -c`, `python3`) e `sudo` são permitidos (sudo usa a
    /// senha do vault sem expô-la). Só comandos catastróficos são recusados.
    pub command: String,
}

/// Modo de escrita do `file_put` (ADR-0004).
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PutMode {
    /// (default) Só cria arquivo NOVO; falha se o path já existir.
    Create,
    /// Sobrescreve arquivo existente. Exige aprovação humana.
    Overwrite,
    /// Anexa ao final do arquivo. Exige aprovação humana.
    Append,
}

impl From<PutMode> for WriteMode {
    fn from(m: PutMode) -> Self {
        match m {
            PutMode::Create => WriteMode::Create,
            PutMode::Overwrite => WriteMode::Overwrite,
            PutMode::Append => WriteMode::Append,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FileGetArgs {
    /// Host alvo (nome ou ID), no escopo.
    pub host: String,
    /// Caminho absoluto do arquivo remoto a ler.
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FilePutArgs {
    /// Host alvo (nome ou ID), no escopo.
    pub host: String,
    /// Caminho absoluto do arquivo remoto.
    pub path: String,
    /// Conteúdo texto a gravar (alternativo a `content_b64`).
    #[serde(default)]
    pub content: Option<String>,
    /// Conteúdo em base64 — para arquivos BINÁRIOS (alternativo a `content`).
    #[serde(default)]
    pub content_b64: Option<String>,
    /// Modo de escrita: create (default), overwrite ou append.
    #[serde(default)]
    pub mode: Option<PutMode>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FileEditArgs {
    /// Host alvo (nome ou ID), no escopo.
    pub host: String,
    /// Caminho absoluto do arquivo EXISTENTE a editar.
    pub path: String,
    /// Texto exato a localizar (deve ocorrer exatamente uma vez).
    pub old_string: String,
    /// Texto de substituição.
    pub new_string: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HealthCheckArgs {
    /// Host alvo (nome ou ID), no escopo.
    pub host: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UploadStartArgs {
    /// Host alvo (nome ou ID), no escopo.
    pub host: String,
    /// Caminho absoluto do arquivo de DESTINO final (só tocado no finish).
    pub path: String,
    /// Modo de escrita no destino: create (default), overwrite ou append.
    #[serde(default)]
    pub mode: Option<PutMode>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UploadChunkArgs {
    /// ID devolvido por `upload_start`.
    pub upload_id: String,
    /// Chunk de dados em base64.
    pub content_b64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UploadFinishArgs {
    /// ID devolvido por `upload_start`.
    pub upload_id: String,
    /// sha256 (hex) do arquivo COMPLETO, calculado pelo chamador. O finish só
    /// move para o destino se o hash remoto conferir.
    pub expected_sha256: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UploadAbortArgs {
    /// ID devolvido por `upload_start`.
    pub upload_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HostsResult {
    pub count: usize,
    pub hosts: Vec<HostView>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HostResult {
    pub host: Option<HostView>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialsResult {
    pub credentials: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExecResult {
    /// "executed" | "denied" | "error"
    pub status: String,
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    /// Explicação (motivo da recusa, erro, decisão de aprovação, etc.).
    pub note: String,
}

impl ExecResult {
    fn simple(status: &str, note: String) -> Self {
        ExecResult {
            status: status.into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            note,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FileGetResult {
    pub status: String,
    pub path: String,
    pub size: usize,
    pub sha256: String,
    pub truncated: bool,
    /// "utf-8" (use `content`) ou "base64" (use `content_b64`). Binários NUNCA
    /// são mutilados como UTF-8 lossy (T4): round-trip get→put preserva bytes.
    pub encoding: String,
    pub content: String,
    /// Presente quando `encoding = "base64"` (arquivo binário).
    pub content_b64: Option<String>,
    pub note: String,
}

impl FileGetResult {
    fn fail(status: &str, path: String, note: String) -> Self {
        FileGetResult {
            status: status.into(),
            path,
            size: 0,
            sha256: String::new(),
            truncated: false,
            encoding: "utf-8".into(),
            content: String::new(),
            content_b64: None,
            note,
        }
    }
}

/// Codifica o conteúdo lido para a resposta (T4): texto UTF-8 vai em
/// `content`; qualquer outra coisa vai em base64 com encoding="base64".
/// Função pura — seam de teste.
fn encode_file_content(bytes: &[u8]) -> (String, String, Option<String>) {
    match std::str::from_utf8(bytes) {
        Ok(s) => ("utf-8".into(), s.to_string(), None),
        Err(_) => ("base64".into(), String::new(), Some(B64.encode(bytes))),
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FileWriteResult {
    pub status: String,
    pub path: String,
    pub bytes: usize,
    pub note: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RefreshResult {
    pub status: String,
    pub total: usize,
    pub visible: usize,
    pub note: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HealthItem {
    pub command: String,
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HealthResult {
    pub status: String,
    pub host: String,
    pub items: Vec<HealthItem>,
    pub note: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UploadStartResult {
    pub status: String,
    pub upload_id: String,
    pub note: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UploadChunkResult {
    pub status: String,
    pub bytes_total: usize,
    pub chunk_sha256: String,
    pub note: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UploadFinishResult {
    pub status: String,
    pub path: String,
    pub bytes: usize,
    pub sha256: String,
    pub note: String,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Gera um upload_id único sem dependência de rand: hash de timestamp + contador.
static UPLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);

fn new_upload_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = UPLOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h = Sha256::new();
    h.update(nanos.to_be_bytes());
    h.update(seq.to_be_bytes());
    h.finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tool_router]
impl RoyalServer {
    pub fn new(inv: Inventory, audit: AuditLog, cfg: Config) -> Self {
        let pool = SshPool::new(ssh::SshSettings::from_config(&cfg));
        let limiter = RateLimiter::new(cfg.limits.max_exec_per_minute);
        RoyalServer {
            inner: Arc::new(Inner {
                inv: RwLock::new(inv),
                audit,
                cfg,
                pool,
                limiter,
                uploads: Mutex::new(HashMap::new()),
            }),
        }
    }

    // ---- helpers ----

    /// Resolve um host (ID → nome exato → substring) dentro do escopo visível.
    /// Substring ambígua vira erro com a lista de candidatos (T4): o chamador
    /// NEGA em vez de executar no host errado. Retorna (motivo_audit, nota).
    fn resolve_host(&self, host: &str) -> Result<HostView, (String, String)> {
        let inv = self.inner.inv.read().unwrap_or_else(|e| e.into_inner());
        match inv.resolve(host) {
            crate::inventory::HostResolution::Found(h) => Ok(h),
            crate::inventory::HostResolution::Ambiguous(cands) => Err((
                "denied:host_ambiguo".into(),
                format!(
                    "host '{host}' ambíguo: {} — use o ID ou o nome exato",
                    cands.join(", ")
                ),
            )),
            crate::inventory::HostResolution::NotFound => Err((
                "denied:host_fora_escopo".into(),
                format!("host '{host}' fora do escopo permitido"),
            )),
        }
    }

    /// Checa o denylist de paths (anti-exfiltração / anti-traversal).
    fn path_denied(&self, path: &str) -> Option<String> {
        if path.trim().is_empty() {
            return Some("path vazio".into());
        }
        if path.contains("..") {
            return Some("path traversal ('..') bloqueado".into());
        }
        let lower = path.to_lowercase();
        self.inner
            .cfg
            .files
            .deny_path_patterns
            .iter()
            .find(|pat| lower.contains(&pat.to_lowercase()))
            .map(|pat| format!("path bloqueado por padrão de segurança '{pat}'"))
    }

    /// Checa a denylist de ESCRITA (anti-persistência, T6). Aplicada só às
    /// tools de escrita — `exec` não passa por ela (a fronteira do exec é o
    /// escopo + a policy anti-catástrofe, por decisão de design).
    fn write_path_denied(&self, path: &str) -> Option<String> {
        let lower = path.to_lowercase();
        self.inner
            .cfg
            .files
            .deny_write_patterns
            .iter()
            .find(|pat| lower.contains(&pat.to_lowercase()))
            .map(|pat| format!("escrita em path de persistência bloqueada '{pat}'"))
    }

    /// Resolve credencial via daemon do vault (async, com timeout interno).
    async fn resolve_cred(&self, host_id: String) -> Result<ResolvedCredential, String> {
        vault::resolve(&self.inner.cfg, &host_id)
            .await
            .map_err(|e| format!("resolução de credencial falhou: {e}"))
    }

    /// Abre o diálogo de aprovação humana (elicitation). Headless / decline /
    /// cancel ⇒ negado. Retorna (aprovado, motivo).
    async fn ask_approval(&self, peer: &Peer<RoleServer>, message: String) -> (bool, String) {
        // Modo agente: servidor não força gate (ambientes sem elicitation, ex.:
        // app Claude Desktop em print mode). A aprovação humana é do AGENTE, via
        // AskUserQuestion ANTES da chamada. Travas duras seguem no servidor.
        if self.inner.cfg.approval_mode == ApprovalMode::Agent {
            return (
                true,
                "modo agente — aprovação delegada ao agente (AskUserQuestion)".into(),
            );
        }
        match peer.elicit::<ApprovalForm>(message).await {
            Ok(Some(form)) if form.approved => (true, "aprovado pelo humano".into()),
            Ok(Some(_)) => (false, "negado pelo humano".into()),
            Ok(None) => (false, "sem resposta na elicitation".into()),
            Err(e) => (false, format!("aprovação indisponível/negada: {e}")),
        }
    }

    /// Validações comuns de escrita: escopo + denylist + ratelimit.
    /// Retorna o HostView alvo ou (status, nota) de recusa já auditada.
    fn check_write_target(
        &self,
        tool: &str,
        host: &str,
        path: &str,
        audit_args: &serde_json::Value,
    ) -> Result<HostView, String> {
        let target = match self.resolve_host(host) {
            Ok(t) => t,
            Err((reason, note)) => {
                self.inner.audit.record(tool, audit_args.clone(), &reason);
                return Err(note);
            }
        };
        if let Some(reason) = self.path_denied(path) {
            self.inner
                .audit
                .record(tool, audit_args.clone(), &format!("denied:{reason}"));
            return Err(reason);
        }
        // T6: denylist de escrita (anti-persistência).
        if let Some(reason) = self.write_path_denied(path) {
            self.inner
                .audit
                .record(tool, audit_args.clone(), &format!("denied:{reason}"));
            return Err(reason);
        }
        if let Err(msg) = self.inner.limiter.check() {
            self.inner
                .audit
                .record(tool, audit_args.clone(), "denied:ratelimit");
            return Err(msg);
        }
        Ok(target)
    }

    // ---- tools de leitura ----

    #[tool(
        name = "query_hosts",
        description = "Lista hosts SSH visíveis ao agente (apenas os do escopo permitido). Filtros opcionais por nome e por pasta/cliente. Nunca retorna credenciais."
    )]
    fn query_hosts(&self, Parameters(args): Parameters<QueryHostsArgs>) -> Json<HostsResult> {
        let inv = self.inner.inv.read().unwrap_or_else(|e| e.into_inner());
        let hosts = inv.query(args.name.as_deref(), args.folder.as_deref());
        self.inner.audit.record(
            "query_hosts",
            serde_json::json!({ "name": args.name, "folder": args.folder }),
            &format!("{} hosts", hosts.len()),
        );
        Json(HostsResult {
            count: hosts.len(),
            hosts,
        })
    }

    #[tool(
        name = "get_host",
        description = "Detalhe de um host pelo ID (sem credencial). Só retorna se o host estiver no escopo permitido."
    )]
    fn get_host(&self, Parameters(args): Parameters<GetHostArgs>) -> Json<HostResult> {
        let inv = self.inner.inv.read().unwrap_or_else(|e| e.into_inner());
        let host = inv.get(&args.id);
        self.inner.audit.record(
            "get_host",
            serde_json::json!({ "id": args.id }),
            if host.is_some() { "found" } else { "not_found" },
        );
        Json(HostResult { host })
    }

    #[tool(
        name = "list_credentials",
        description = "Lista apenas os NOMES de usuário/credencial dos hosts no escopo. Jamais valores."
    )]
    fn list_credentials(&self) -> Json<CredentialsResult> {
        let inv = self.inner.inv.read().unwrap_or_else(|e| e.into_inner());
        let creds = inv.credentials();
        self.inner.audit.record(
            "list_credentials",
            serde_json::json!({}),
            &format!("{} nomes", creds.len()),
        );
        Json(CredentialsResult { credentials: creds })
    }

    #[tool(
        name = "refresh_inventory",
        description = "Recarrega o inventário a partir do documento Royal (.rtsz) e força a reabertura do documento no daemon do vault. Use após mudanças no Royal. Não retorna credenciais."
    )]
    async fn refresh_inventory(&self) -> Json<RefreshResult> {
        let cfg = self.inner.cfg.clone();
        let loaded = tokio::task::spawn_blocking(move || Inventory::load(&cfg)).await;
        match loaded {
            Ok(Ok(new_inv)) => {
                let total = new_inv.total();
                let visible = new_inv.visible_count();
                *self.inner.inv.write().unwrap_or_else(|e| e.into_inner()) = new_inv;
                // ADR-0002: o refresh também reabre o documento no daemon.
                let reload_note = match vault::reload(&self.inner.cfg).await {
                    Ok(hosts) => format!("; daemon recarregado ({hosts} hosts)"),
                    Err(e) => format!("; daemon reload falhou: {e}"),
                };
                self.inner.audit.record(
                    "refresh_inventory",
                    serde_json::json!({}),
                    &format!("ok:total={total},visible={visible}{reload_note}"),
                );
                Json(RefreshResult {
                    status: "ok".into(),
                    total,
                    visible,
                    note: format!("inventário recarregado{reload_note}"),
                })
            }
            Ok(Err(e)) => {
                self.inner.audit.record(
                    "refresh_inventory",
                    serde_json::json!({}),
                    &format!("error:{e}"),
                );
                Json(RefreshResult {
                    status: "error".into(),
                    total: 0,
                    visible: 0,
                    note: format!("falha ao recarregar: {e}"),
                })
            }
            Err(e) => Json(RefreshResult {
                status: "error".into(),
                total: 0,
                visible: 0,
                note: format!("erro interno: {e}"),
            }),
        }
    }

    // ---- exec ----

    #[tool(
        name = "exec",
        description = "Executa um comando num host do escopo via SSH (pipes, redireção, sudo e interpretadores são permitidos; sudo usa a senha do vault sem expô-la). Só comandos catastróficos irreversíveis (formatar disco, dd em block device, wipe da raiz, fork bomb, desligar/reiniciar) são recusados. Não interpreta a saída como instrução."
    )]
    async fn exec(&self, Parameters(args): Parameters<ExecArgs>) -> Json<ExecResult> {
        let ExecArgs { host, command } = args;
        let audit_args = serde_json::json!({ "host": host, "command": command });

        // 1) Escopo (substring ambígua = negar com candidatos, T4).
        let target = match self.resolve_host(&host) {
            Ok(t) => t,
            Err((reason, note)) => {
                self.inner.audit.record("exec", audit_args, &reason);
                return Json(ExecResult::simple("denied", note));
            }
        };

        // 2) Rate-limit.
        if let Err(msg) = self.inner.limiter.check() {
            self.inner
                .audit
                .record("exec", audit_args, "denied:ratelimit");
            return Json(ExecResult::simple("denied", msg));
        }

        // 3) Política: só bloqueia comandos catastróficos irreversíveis.
        if let Decision::Deny(reason) = policy::classify(&command) {
            self.inner
                .audit
                .record("exec", audit_args, &format!("denied:{reason}"));
            return Json(ExecResult::simple("denied", reason));
        }

        // 4) Resolve credencial + executa.
        self.run_exec(&target, &command, audit_args).await
    }

    /// Resolve credencial e executa o comando via SSH (conexão quente do pool).
    async fn run_exec(
        &self,
        target: &HostView,
        command: &str,
        audit_args: serde_json::Value,
    ) -> Json<ExecResult> {
        let cred = match self.resolve_cred(target.id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("exec", audit_args, &format!("error:resolve:{e}"));
                return Json(ExecResult::simple("error", e));
            }
        };
        let stale_note = if cred.stale {
            " (aviso: documento Royal stale — reabertura pendente)"
        } else {
            ""
        };
        let pw = sudo_password(&cred);
        match ssh::exec(
            &self.inner.pool,
            &target.uri,
            target.port,
            &cred,
            command,
            pw,
        )
        .await
        {
            Ok(out) => {
                self.inner.audit.record(
                    "exec",
                    audit_args,
                    &format!("executed:exit={:?}", out.exit_code),
                );
                Json(ExecResult {
                    status: "executed".into(),
                    exit_code: out.exit_code,
                    stdout: out.stdout,
                    stderr: out.stderr,
                    truncated: out.truncated,
                    note: stale_note.to_string(),
                })
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("exec", audit_args, &format!("error:ssh:{e}"));
                Json(ExecResult::simple(
                    "error",
                    format!("falha SSH: {e}{stale_note}"),
                ))
            }
        }
    }

    #[tool(
        name = "health_check",
        description = "Runbook de diagnóstico read-only: roda um conjunto fixo de comandos seguros (hostname, uptime, df) num host do escopo e devolve a saída de cada um."
    )]
    async fn health_check(
        &self,
        Parameters(args): Parameters<HealthCheckArgs>,
    ) -> Json<HealthResult> {
        let HealthCheckArgs { host } = args;
        let audit_args = serde_json::json!({ "host": host, "macro": "health_check" });

        let target = match self.resolve_host(&host) {
            Ok(t) => t,
            Err((reason, note)) => {
                self.inner.audit.record("health_check", audit_args, &reason);
                return Json(HealthResult {
                    status: "denied".into(),
                    host,
                    items: vec![],
                    note,
                });
            }
        };
        if let Err(msg) = self.inner.limiter.check() {
            self.inner
                .audit
                .record("health_check", audit_args, "denied:ratelimit");
            return Json(HealthResult {
                status: "denied".into(),
                host,
                items: vec![],
                note: msg,
            });
        }
        let cred = match self.resolve_cred(target.id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("health_check", audit_args, &format!("error:resolve:{e}"));
                return Json(HealthResult {
                    status: "error".into(),
                    host,
                    items: vec![],
                    note: e,
                });
            }
        };

        const CMDS: &[&str] = &["hostname", "uptime", "df -h"];
        let mut items = Vec::new();
        for cmd in CMDS {
            match ssh::exec(&self.inner.pool, &target.uri, target.port, &cred, cmd, None).await {
                Ok(out) => items.push(HealthItem {
                    command: cmd.to_string(),
                    exit_code: out.exit_code,
                    stdout: out.stdout,
                    stderr: out.stderr,
                }),
                Err(e) => items.push(HealthItem {
                    command: cmd.to_string(),
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("falha: {e}"),
                }),
            }
        }
        self.inner
            .audit
            .record("health_check", audit_args, "executed");
        Json(HealthResult {
            status: "executed".into(),
            host,
            items,
            note: String::new(),
        })
    }

    // ---- file ops ----

    #[tool(
        name = "file_get",
        description = "Lê um arquivo de um host do escopo via SFTP (com cap de tamanho). Paths sensíveis (chaves, shadow, etc.) são bloqueados. Registra hash e tamanho no audit."
    )]
    async fn file_get(&self, Parameters(args): Parameters<FileGetArgs>) -> Json<FileGetResult> {
        let FileGetArgs { host, path } = args;
        let audit_args = serde_json::json!({ "host": host, "path": path });

        let target = match self.resolve_host(&host) {
            Ok(t) => t,
            Err((reason, note)) => {
                self.inner.audit.record("file_get", audit_args, &reason);
                return Json(FileGetResult::fail("denied", path, note));
            }
        };
        if let Some(reason) = self.path_denied(&path) {
            self.inner
                .audit
                .record("file_get", audit_args, &format!("denied:{reason}"));
            return Json(FileGetResult::fail("denied", path, reason));
        }
        if let Err(msg) = self.inner.limiter.check() {
            self.inner
                .audit
                .record("file_get", audit_args, "denied:ratelimit");
            return Json(FileGetResult::fail("denied", path, msg));
        }
        let cred = match self.resolve_cred(target.id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("file_get", audit_args, &format!("error:resolve:{e}"));
                return Json(FileGetResult::fail("error", path, e));
            }
        };
        let max = self.inner.cfg.files.max_get_bytes;
        match ssh::file_get(
            &self.inner.pool,
            &target.uri,
            target.port,
            &cred,
            &path,
            max,
        )
        .await
        {
            Ok(fc) => {
                let sha = sha256_hex(&fc.bytes);
                let size = fc.bytes.len();
                self.inner.audit.record(
                    "file_get",
                    audit_args,
                    &format!("read:size={size},sha256={sha},truncated={}", fc.truncated),
                );
                let (encoding, content, content_b64) = encode_file_content(&fc.bytes);
                Json(FileGetResult {
                    status: "read".into(),
                    path,
                    size,
                    sha256: sha,
                    truncated: fc.truncated,
                    encoding,
                    content,
                    content_b64,
                    note: String::new(),
                })
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("file_get", audit_args, &format!("error:{e}"));
                Json(FileGetResult::fail(
                    "error",
                    path,
                    format!("falha ao ler: {e}"),
                ))
            }
        }
    }

    #[tool(
        name = "file_put",
        description = "Grava um arquivo num host do escopo via SFTP. Modos: create (default; só arquivo NOVO, falha se existir), overwrite (sobrescreve; exige aprovação), append (anexa; exige aprovação). Aceita texto (`content`) ou binário em base64 (`content_b64`). Para arquivos grandes use upload_start/upload_chunk/upload_finish. Paths sensíveis são bloqueados."
    )]
    async fn file_put(
        &self,
        Parameters(args): Parameters<FilePutArgs>,
        peer: Peer<RoleServer>,
    ) -> Json<FileWriteResult> {
        let mode = args.mode.unwrap_or(PutMode::Create);
        let path = args.path.clone();
        let data = match (&args.content, &args.content_b64) {
            (Some(text), None) => text.as_bytes().to_vec(),
            (None, Some(b64s)) => match B64.decode(b64s.trim()) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Json(FileWriteResult {
                        status: "denied".into(),
                        path,
                        bytes: 0,
                        note: format!("content_b64 inválido: {e}"),
                    });
                }
            },
            _ => {
                return Json(FileWriteResult {
                    status: "denied".into(),
                    path,
                    bytes: 0,
                    note: "informe exatamente um de: content (texto) ou content_b64".into(),
                });
            }
        };
        let audit_args = serde_json::json!({
            "host": args.host, "path": path, "bytes": data.len(),
            "mode": format!("{mode:?}").to_lowercase(),
        });

        let target = match self.check_write_target("file_put", &args.host, &path, &audit_args) {
            Ok(t) => t,
            Err(note) => {
                return Json(FileWriteResult {
                    status: "denied".into(),
                    path,
                    bytes: 0,
                    note,
                });
            }
        };
        if data.len() > self.inner.cfg.files.max_put_bytes {
            self.inner
                .audit
                .record("file_put", audit_args, "denied:max_put_bytes");
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: format!(
                    "conteúdo excede max_put_bytes ({}); use upload em chunks",
                    self.inner.cfg.files.max_put_bytes
                ),
            });
        }

        // Aprovação humana (mutação). Create também pede (comportamento atual);
        // overwrite/append explicitam o risco na mensagem.
        let msg = match mode {
            PutMode::Create => format!(
                "Aprovar criação de arquivo NOVO?\n\nHost: {} ({}:{})\nPath: {}\nTamanho: {} bytes\n(NÃO sobrescreve: falha se já existir)",
                target.name,
                target.uri,
                target.port,
                path,
                data.len()
            ),
            PutMode::Overwrite => format!(
                "Aprovar SOBRESCRITA de arquivo?\n\nHost: {} ({}:{})\nPath: {}\nTamanho novo: {} bytes\n(O conteúdo atual será substituído)",
                target.name,
                target.uri,
                target.port,
                path,
                data.len()
            ),
            PutMode::Append => format!(
                "Aprovar APPEND em arquivo?\n\nHost: {} ({}:{})\nPath: {}\nBytes a anexar: {}\n(O conteúdo atual é preservado)",
                target.name,
                target.uri,
                target.port,
                path,
                data.len()
            ),
        };
        let (ok, why) = self.ask_approval(&peer, msg).await;
        if !ok {
            self.inner
                .audit
                .record("file_put", audit_args, &format!("denied:approval:{why}"));
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: format!("não gravado — {why}"),
            });
        }

        let cred = match self.resolve_cred(target.id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("file_put", audit_args, &format!("error:resolve:{e}"));
                return Json(FileWriteResult {
                    status: "error".into(),
                    path,
                    bytes: 0,
                    note: e,
                });
            }
        };
        match ssh::file_put_mode(
            &self.inner.pool,
            &target.uri,
            target.port,
            &cred,
            &path,
            &data,
            mode.into(),
        )
        .await
        {
            Ok(()) => {
                let verb = match mode {
                    PutMode::Create => "created",
                    PutMode::Overwrite => "overwritten",
                    PutMode::Append => "appended",
                };
                // T6: sha256 do conteúdo no audit (paridade forense com
                // file_edit e upload em chunks).
                let content_sha = sha256_hex(&data);
                self.inner.audit.record(
                    "file_put",
                    audit_args,
                    &format!("{verb}:bytes={},sha256={content_sha}", data.len()),
                );
                Json(FileWriteResult {
                    status: verb.into(),
                    path,
                    bytes: data.len(),
                    note: String::new(),
                })
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("file_put", audit_args, &format!("error:{e}"));
                Json(FileWriteResult {
                    status: "error".into(),
                    path,
                    bytes: 0,
                    note: format!("falha ao gravar: {e}"),
                })
            }
        }
    }

    #[tool(
        name = "file_edit",
        description = "Edita um arquivo EXISTENTE num host do escopo via SFTP, substituindo uma ocorrência exata de texto. Exige aprovação humana no chat (é uma sobrescrita controlada). Paths sensíveis são bloqueados."
    )]
    async fn file_edit(
        &self,
        Parameters(args): Parameters<FileEditArgs>,
        peer: Peer<RoleServer>,
    ) -> Json<FileWriteResult> {
        let FileEditArgs {
            host,
            path,
            old_string,
            new_string,
        } = args;
        // Hashes (não o texto em claro) no audit p/ forense sem vazar conteúdo.
        let audit_args = serde_json::json!({
            "host": host,
            "path": path,
            "old_sha256": sha256_hex(old_string.as_bytes()),
            "new_sha256": sha256_hex(new_string.as_bytes()),
        });

        let target = match self.resolve_host(&host) {
            Ok(t) => t,
            Err((reason, note)) => {
                self.inner.audit.record("file_edit", audit_args, &reason);
                return Json(FileWriteResult {
                    status: "denied".into(),
                    path,
                    bytes: 0,
                    note,
                });
            }
        };
        if let Some(reason) = self.path_denied(&path) {
            self.inner
                .audit
                .record("file_edit", audit_args, &format!("denied:{reason}"));
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: reason,
            });
        }
        // T6: denylist de escrita (anti-persistência).
        if let Some(reason) = self.write_path_denied(&path) {
            self.inner
                .audit
                .record("file_edit", audit_args, &format!("denied:{reason}"));
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: reason,
            });
        }
        if old_string.is_empty() {
            self.inner
                .audit
                .record("file_edit", audit_args, "denied:old_string_vazio");
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: "old_string vazio".into(),
            });
        }
        if let Err(msg) = self.inner.limiter.check() {
            self.inner
                .audit
                .record("file_edit", audit_args, "denied:ratelimit");
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: msg,
            });
        }

        let cred = match self.resolve_cred(target.id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("file_edit", audit_args, &format!("error:resolve:{e}"));
                return Json(FileWriteResult {
                    status: "error".into(),
                    path,
                    bytes: 0,
                    note: e,
                });
            }
        };

        // Lê o conteúdo atual e valida o replace ANTES de pedir aprovação.
        let max = self.inner.cfg.files.max_get_bytes;
        let current = match ssh::file_get(
            &self.inner.pool,
            &target.uri,
            target.port,
            &cred,
            &path,
            max,
        )
        .await
        {
            Ok(fc) if fc.truncated => {
                return Json(FileWriteResult {
                    status: "denied".into(),
                    path,
                    bytes: 0,
                    note: "arquivo maior que o cap de leitura; edição abortada".into(),
                });
            }
            Ok(fc) => match String::from_utf8(fc.bytes) {
                Ok(s) => s,
                Err(_) => {
                    return Json(FileWriteResult {
                        status: "denied".into(),
                        path,
                        bytes: 0,
                        note: "arquivo não é texto UTF-8; edição não suportada".into(),
                    });
                }
            },
            Err(e) => {
                self.inner
                    .audit
                    .record("file_edit", audit_args, &format!("error:read:{e}"));
                return Json(FileWriteResult {
                    status: "error".into(),
                    path,
                    bytes: 0,
                    note: format!("falha ao ler arquivo p/ editar (existe?): {e}"),
                });
            }
        };

        let occurrences = current.matches(&old_string).count();
        if occurrences == 0 {
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: "old_string não encontrado no arquivo".into(),
            });
        }
        if occurrences > 1 {
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: format!("old_string ambíguo: {occurrences} ocorrências (exija unicidade)"),
            });
        }
        let updated = current.replacen(&old_string, &new_string, 1);
        let current_sha = sha256_hex(current.as_bytes());

        // Aprovação humana (sobrescrita de arquivo existente).
        let msg = format!(
            "Aprovar EDIÇÃO de arquivo existente?\n\nHost: {} ({}:{})\nPath: {}\n- {} bytes → {} bytes\n(substitui 1 ocorrência exata)",
            target.name,
            target.uri,
            target.port,
            path,
            current.len(),
            updated.len()
        );
        let (ok, why) = self.ask_approval(&peer, msg).await;
        if !ok {
            self.inner
                .audit
                .record("file_edit", audit_args, &format!("denied:approval:{why}"));
            return Json(FileWriteResult {
                status: "denied".into(),
                path,
                bytes: 0,
                note: format!("não editado — {why}"),
            });
        }

        // Revalida logo antes de gravar: fecha a janela TOCTOU entre a leitura
        // (que validou o replace e foi mostrada na aprovação) e a escrita. Se o
        // arquivo mudou/sumiu no host nesse meio-tempo, aborta sem gravar.
        match ssh::file_get(
            &self.inner.pool,
            &target.uri,
            target.port,
            &cred,
            &path,
            max,
        )
        .await
        {
            Ok(fc) if !fc.truncated && sha256_hex(&fc.bytes) == current_sha => {}
            Ok(_) => {
                self.inner
                    .audit
                    .record("file_edit", audit_args, "denied:toctou_mudou");
                return Json(FileWriteResult {
                    status: "denied".into(),
                    path,
                    bytes: 0,
                    note: "arquivo mudou no host desde a leitura aprovada; edição abortada".into(),
                });
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("file_edit", audit_args, &format!("error:reread:{e}"));
                return Json(FileWriteResult {
                    status: "error".into(),
                    path,
                    bytes: 0,
                    note: format!("falha ao revalidar antes de gravar: {e}"),
                });
            }
        }

        match ssh::file_overwrite(
            &self.inner.pool,
            &target.uri,
            target.port,
            &cred,
            &path,
            updated.as_bytes(),
        )
        .await
        {
            Ok(()) => {
                self.inner.audit.record(
                    "file_edit",
                    audit_args,
                    &format!("edited:bytes={}", updated.len()),
                );
                Json(FileWriteResult {
                    status: "edited".into(),
                    path,
                    bytes: updated.len(),
                    note: String::new(),
                })
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("file_edit", audit_args, &format!("error:write:{e}"));
                return Json(FileWriteResult {
                    status: "error".into(),
                    path,
                    bytes: 0,
                    note: format!("falha ao gravar: {e}"),
                });
            }
        }
    }

    // ---- upload em chunks (ADR-0004) ----

    #[tool(
        name = "upload_start",
        description = "Inicia um upload em chunks para arquivos grandes: cria um temporário no host e devolve um upload_id. O destino final só é tocado no upload_finish, após verificação de sha256. Modos: create (default), overwrite, append. Exige aprovação humana."
    )]
    async fn upload_start(
        &self,
        Parameters(args): Parameters<UploadStartArgs>,
        peer: Peer<RoleServer>,
    ) -> Json<UploadStartResult> {
        let mode = args.mode.unwrap_or(PutMode::Create);
        let audit_args = serde_json::json!({
            "host": args.host, "path": args.path,
            "mode": format!("{mode:?}").to_lowercase(),
        });

        let target =
            match self.check_write_target("upload_start", &args.host, &args.path, &audit_args) {
                Ok(t) => t,
                Err(note) => {
                    return Json(UploadStartResult {
                        status: "denied".into(),
                        upload_id: String::new(),
                        note,
                    });
                }
            };

        let msg = format!(
            "Aprovar upload em chunks?\n\nHost: {} ({}:{})\nDestino: {}\nModo: {}\n(O destino final só é tocado após verificação de sha256 no finish)",
            target.name,
            target.uri,
            target.port,
            args.path,
            format!("{mode:?}").to_lowercase()
        );
        let (ok, why) = self.ask_approval(&peer, msg).await;
        if !ok {
            self.inner.audit.record(
                "upload_start",
                audit_args,
                &format!("denied:approval:{why}"),
            );
            return Json(UploadStartResult {
                status: "denied".into(),
                upload_id: String::new(),
                note: format!("não iniciado — {why}"),
            });
        }

        let cred = match self.resolve_cred(target.id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_start", audit_args, &format!("error:resolve:{e}"));
                return Json(UploadStartResult {
                    status: "error".into(),
                    upload_id: String::new(),
                    note: e,
                });
            }
        };

        let upload_id = new_upload_id();
        let temp_path = format!("/tmp/.royal-mcp-upload-{upload_id}");
        match ssh::upload_temp_create(
            &self.inner.pool,
            &target.uri,
            target.port,
            &cred,
            &temp_path,
        )
        .await
        {
            Ok(()) => {
                self.inner
                    .uploads
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        upload_id.clone(),
                        UploadState {
                            host_id: target.id.clone(),
                            uri: target.uri.clone(),
                            port: target.port,
                            dest: args.path.clone(),
                            temp_path,
                            mode: mode.into(),
                            bytes: 0,
                        },
                    );
                self.inner.audit.record(
                    "upload_start",
                    audit_args,
                    &format!("started:upload_id={upload_id}"),
                );
                Json(UploadStartResult {
                    status: "started".into(),
                    upload_id,
                    note: "temporário criado; envie chunks com upload_chunk".into(),
                })
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_start", audit_args, &format!("error:{e}"));
                Json(UploadStartResult {
                    status: "error".into(),
                    upload_id: String::new(),
                    note: format!("falha ao criar temporário: {e}"),
                })
            }
        }
    }

    #[tool(
        name = "upload_chunk",
        description = "Anexa um chunk (base64) ao upload iniciado por upload_start. Devolve o sha256 do chunk e o total acumulado."
    )]
    async fn upload_chunk(
        &self,
        Parameters(args): Parameters<UploadChunkArgs>,
    ) -> Json<UploadChunkResult> {
        let data = match B64.decode(args.content_b64.trim()) {
            Ok(d) => d,
            Err(e) => {
                return Json(UploadChunkResult {
                    status: "denied".into(),
                    bytes_total: 0,
                    chunk_sha256: String::new(),
                    note: format!("content_b64 inválido: {e}"),
                });
            }
        };
        let audit_args =
            serde_json::json!({ "upload_id": args.upload_id, "chunk_bytes": data.len() });

        let (host_id, uri, port, temp_path, total) = {
            let uploads = self.inner.uploads.lock().unwrap_or_else(|e| e.into_inner());
            match uploads.get(&args.upload_id) {
                Some(u) => (
                    u.host_id.clone(),
                    u.uri.clone(),
                    u.port,
                    u.temp_path.clone(),
                    u.bytes,
                ),
                None => {
                    return Json(UploadChunkResult {
                        status: "denied".into(),
                        bytes_total: 0,
                        chunk_sha256: String::new(),
                        note: "upload_id desconhecido (expirou? abortado?)".into(),
                    });
                }
            }
        };
        if let Err(msg) = self.inner.limiter.check() {
            self.inner
                .audit
                .record("upload_chunk", audit_args, "denied:ratelimit");
            return Json(UploadChunkResult {
                status: "denied".into(),
                bytes_total: total,
                chunk_sha256: String::new(),
                note: msg,
            });
        }
        let cred = match self.resolve_cred(host_id).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_chunk", audit_args, &format!("error:resolve:{e}"));
                return Json(UploadChunkResult {
                    status: "error".into(),
                    bytes_total: total,
                    chunk_sha256: String::new(),
                    note: e,
                });
            }
        };
        match ssh::upload_temp_append(&self.inner.pool, &uri, port, &cred, &temp_path, &data).await
        {
            Ok(()) => {
                let chunk_sha = sha256_hex(&data);
                let new_total = total + data.len();
                let mut uploads = self.inner.uploads.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(u) = uploads.get_mut(&args.upload_id) {
                    u.bytes = new_total;
                }
                self.inner.audit.record(
                    "upload_chunk",
                    audit_args,
                    &format!("appended:total={new_total},chunk_sha256={chunk_sha}"),
                );
                Json(UploadChunkResult {
                    status: "appended".into(),
                    bytes_total: new_total,
                    chunk_sha256: chunk_sha,
                    note: String::new(),
                })
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_chunk", audit_args, &format!("error:{e}"));
                Json(UploadChunkResult {
                    status: "error".into(),
                    bytes_total: total,
                    chunk_sha256: String::new(),
                    note: format!("falha ao anexar chunk: {e}"),
                })
            }
        }
    }

    #[tool(
        name = "upload_finish",
        description = "Finaliza um upload em chunks: verifica o sha256 do arquivo completo e, conferindo, move o temporário para o destino respeitando o modo (create/overwrite/append). Se o hash não conferir, o destino NÃO é tocado."
    )]
    async fn upload_finish(
        &self,
        Parameters(args): Parameters<UploadFinishArgs>,
    ) -> Json<UploadFinishResult> {
        let state = {
            let mut uploads = self.inner.uploads.lock().unwrap_or_else(|e| e.into_inner());
            uploads.remove(&args.upload_id)
        };
        let Some(state) = state else {
            return Json(UploadFinishResult {
                status: "denied".into(),
                path: String::new(),
                bytes: 0,
                sha256: String::new(),
                note: "upload_id desconhecido (expirou? abortado?)".into(),
            });
        };
        let audit_args = serde_json::json!({
            "upload_id": args.upload_id, "dest": state.dest, "bytes": state.bytes,
        });
        let cred = match self.resolve_cred(state.host_id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_finish", audit_args, &format!("error:resolve:{e}"));
                return Json(UploadFinishResult {
                    status: "error".into(),
                    path: state.dest,
                    bytes: state.bytes,
                    sha256: String::new(),
                    note: e,
                });
            }
        };

        // 1) Verificação de integridade: hash do temporário completo.
        let bytes = match ssh::upload_temp_read(
            &self.inner.pool,
            &state.uri,
            state.port,
            &cred,
            &state.temp_path,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_finish", audit_args, &format!("error:read:{e}"));
                return Json(UploadFinishResult {
                    status: "error".into(),
                    path: state.dest,
                    bytes: state.bytes,
                    sha256: String::new(),
                    note: format!("falha ao ler temporário para verificação: {e}"),
                });
            }
        };
        let actual_sha = sha256_hex(&bytes);
        if !actual_sha.eq_ignore_ascii_case(args.expected_sha256.trim()) {
            self.inner.audit.record(
                "upload_finish",
                audit_args,
                &format!(
                    "denied:sha256_mismatch:expected={},actual={actual_sha}",
                    args.expected_sha256
                ),
            );
            // Limpa o temporário: sem finish, ele nunca vira destino.
            let _ = ssh::remote_remove(
                &self.inner.pool,
                &state.uri,
                state.port,
                &cred,
                &state.temp_path,
            )
            .await;
            return Json(UploadFinishResult {
                status: "denied".into(),
                path: state.dest,
                bytes: bytes.len(),
                sha256: actual_sha,
                note: "sha256 não confere; destino NÃO tocado e temporário removido".into(),
            });
        }

        // 2) Finalização conforme o modo.
        let finish_result = match state.mode {
            WriteMode::Create => {
                match ssh::remote_exists(
                    &self.inner.pool,
                    &state.uri,
                    state.port,
                    &cred,
                    &state.dest,
                )
                .await
                {
                    Ok(true) => Err(anyhow::anyhow!("destino já existe (modo create)")),
                    Ok(false) => {
                        ssh::remote_rename(
                            &self.inner.pool,
                            &state.uri,
                            state.port,
                            &cred,
                            &state.temp_path,
                            &state.dest,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
            WriteMode::Overwrite => {
                ssh::remote_rename(
                    &self.inner.pool,
                    &state.uri,
                    state.port,
                    &cred,
                    &state.temp_path,
                    &state.dest,
                )
                .await
            }
            WriteMode::Append => {
                match ssh::file_put_mode(
                    &self.inner.pool,
                    &state.uri,
                    state.port,
                    &cred,
                    &state.dest,
                    &bytes,
                    WriteMode::Append,
                )
                .await
                {
                    Ok(()) => {
                        ssh::remote_remove(
                            &self.inner.pool,
                            &state.uri,
                            state.port,
                            &cred,
                            &state.temp_path,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
        };

        match finish_result {
            Ok(()) => {
                let verb = match state.mode {
                    WriteMode::Create => "created",
                    WriteMode::Overwrite => "overwritten",
                    WriteMode::Append => "appended",
                };
                self.inner.audit.record(
                    "upload_finish",
                    audit_args,
                    &format!("{verb}:bytes={},sha256={actual_sha}", bytes.len()),
                );
                Json(UploadFinishResult {
                    status: verb.into(),
                    path: state.dest,
                    bytes: bytes.len(),
                    sha256: actual_sha,
                    note: String::new(),
                })
            }
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_finish", audit_args, &format!("error:{e}"));
                Json(UploadFinishResult {
                    status: "error".into(),
                    path: state.dest,
                    bytes: bytes.len(),
                    sha256: actual_sha,
                    note: format!(
                        "falha na finalização (temporário preservado em {}): {e}",
                        state.temp_path
                    ),
                })
            }
        }
    }

    #[tool(
        name = "upload_abort",
        description = "Aborta um upload em chunks: remove o temporário remoto e descarta o estado. O destino nunca é tocado."
    )]
    async fn upload_abort(
        &self,
        Parameters(args): Parameters<UploadAbortArgs>,
    ) -> Json<FileWriteResult> {
        let state = {
            let mut uploads = self.inner.uploads.lock().unwrap_or_else(|e| e.into_inner());
            uploads.remove(&args.upload_id)
        };
        let audit_args = serde_json::json!({ "upload_id": args.upload_id });
        let Some(state) = state else {
            return Json(FileWriteResult {
                status: "denied".into(),
                path: String::new(),
                bytes: 0,
                note: "upload_id desconhecido".into(),
            });
        };
        let cred = match self.resolve_cred(state.host_id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.inner
                    .audit
                    .record("upload_abort", audit_args, &format!("error:resolve:{e}"));
                return Json(FileWriteResult {
                    status: "error".into(),
                    path: state.dest,
                    bytes: state.bytes,
                    note: e,
                });
            }
        };
        let _ = ssh::remote_remove(
            &self.inner.pool,
            &state.uri,
            state.port,
            &cred,
            &state.temp_path,
        )
        .await;
        self.inner
            .audit
            .record("upload_abort", audit_args, "aborted");
        Json(FileWriteResult {
            status: "aborted".into(),
            path: state.dest,
            bytes: state.bytes,
            note: "temporário removido; destino não tocado".into(),
        })
    }
}

#[tool_handler]
impl ServerHandler for RoyalServer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t4_texto_utf8_vai_em_content() {
        let (enc, content, b64) = encode_file_content("olá royal\n".as_bytes());
        assert_eq!(enc, "utf-8");
        assert_eq!(content, "olá royal\n");
        assert!(b64.is_none());
    }

    #[test]
    fn t4_binario_vai_em_base64_sem_mutilacao() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let (enc, content, b64) = encode_file_content(&bytes);
        assert_eq!(enc, "base64");
        assert!(content.is_empty());
        let decoded = B64.decode(b64.unwrap()).unwrap();
        assert_eq!(decoded, bytes, "round-trip deve preservar todos os bytes");
    }

    #[test]
    fn t4_utf8_com_bytes_invalidos_no_meio_vai_em_base64() {
        let bytes = b"texto \xFF\xFE binario";
        let (enc, _, b64) = encode_file_content(bytes);
        assert_eq!(enc, "base64");
        assert_eq!(B64.decode(b64.unwrap()).unwrap(), bytes);
    }

    #[test]
    fn t4_arquivo_vazio_e_texto() {
        let (enc, content, b64) = encode_file_content(b"");
        assert_eq!(enc, "utf-8");
        assert!(content.is_empty());
        assert!(b64.is_none());
    }
}
