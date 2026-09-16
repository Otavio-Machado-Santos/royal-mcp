//! Vault — resolução de credencial via **daemon pwsh persistente** (ADR-0001).
//! Único módulo que toca o segredo. O daemon (`ps/vault-daemon.ps1`) abre o
//! Documento Royal uma vez e atende pedidos por stdin/stdout (JSON por linha);
//! este módulo gerencia o processo (spawn, respawn sob demanda, mutex async) e
//! materializa o segredo em `Secret` (zeroize no drop).
//!
//! Resiliência (T1): todo pedido ao daemon tem timeout — um pwsh travado NUNCA
//! congela o servidor. Timeout, erro de transporte e resposta não-JSON são
//! classificados como falha de daemon: o processo é descartado e o pedido é
//! retentado UMA vez com respawn. Um circuit breaker limita respawns caros.
//! Erros vindos do daemon são sanitizados antes de chegar ao agente/audit
//! (a Fronteira de Credencial vale também para exceções).
//!
//! Invalidação do documento (ADR-0002): o próprio daemon compara o mtime do
//! `.rtsz` antes de cada resolução e reabre quando muda; `reload()` força a
//! reabertura (chamado por `refresh_inventory`).
//!
//! A checagem de escopo (host permitido) é responsabilidade do CHAMADOR — este
//! módulo só resolve por ID já validado. O segredo nunca é logado nem
//! serializado: transita só do daemon para este processo.
use crate::config::Config;
use crate::secret::Secret;
use anyhow::{Context, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, OnceCell};
use tokio::time::timeout;
use zeroize::Zeroize;

/// Timeout de um pedido ao daemon (resolve/reload). O daemon quente responde
/// em ms; a reabertura do documento (mtime mudou) leva ~10-20s — 30s cobre.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Prontidão na partida: cold start com import do módulo Royal + decrypt.
const READY_TIMEOUT: Duration = Duration::from_secs(90);
/// Circuit breaker de respawns: no máximo N por janela (respawn custa ~15-20s).
const MAX_RESPAWNS: u32 = 3;
const RESPAWN_WINDOW: Duration = Duration::from_secs(300);
/// Teto da mensagem de erro do daemon que chega ao agente/audit.
const MAX_ERROR_LEN: usize = 160;

/// Material de autenticação resolvido (sem expor o valor). Consumido pelo motor
/// SSH (senha → `authenticate_password`; chave+passphrase → `authenticate_publickey`).
pub enum AuthMaterial {
    Password(Secret),
    Key {
        content: Secret,
        passphrase: Option<Secret>,
    },
    None,
}

pub struct ResolvedCredential {
    pub username: String,
    pub auth: AuthMaterial,
    /// `true` quando o daemon atendeu com o documento ANTERIOR porque a
    /// reabertura falhou (Royal TS salvando o `.rtsz`). Informativo.
    pub stale: bool,
}

#[derive(Debug, Deserialize)]
struct ResolveRaw {
    #[serde(default)]
    username: String,
    auth: String,
    password: Option<String>,
    key_content: Option<String>,
    passphrase: Option<String>,
    #[serde(default)]
    stale: bool,
}

// ---------------------------------------------------------------------------
// Falhas do daemon (classificação — seam de teste)
// ---------------------------------------------------------------------------

/// Como um pedido ao daemon falhou. Todos os três tipos disparam o mesmo
/// caminho: descartar o processo e retentar UMA vez com respawn.
#[derive(Debug, PartialEq, Eq)]
pub enum DaemonFailure {
    /// Não respondeu dentro do timeout (pwsh travado/pendurado).
    Timeout,
    /// Pipe fechado, processo morto, EOF inesperado.
    Transport,
    /// Respondeu algo que não é o JSON do protocolo (desalinhamento).
    Protocol,
    /// JSON válido com campo `error` (falha de negócio — NÃO respawna).
    Business,
}

fn classify_line_failure(kind: &DaemonFailure) -> bool {
    // Apenas Business não respawna; os demais descartam e retentam.
    !matches!(kind, DaemonFailure::Business)
}

// ---------------------------------------------------------------------------
// Sanitização de erros (seam de teste)
// ---------------------------------------------------------------------------

/// Sanitiza uma mensagem de erro vinda do daemon antes de expor ao
/// agente/audit: uma única linha (whitespace colapsado), truncada. Exceções do
/// módulo Royal podem carregar payload inesperado — a Fronteira de Credencial
/// vale para erros.
fn sanitize_daemon_error(raw: &str) -> String {
    let one_line = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > MAX_ERROR_LEN {
        let mut s: String = one_line.chars().take(MAX_ERROR_LEN).collect();
        s.push('…');
        s
    } else {
        one_line
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker de respawns (seam de teste)
// ---------------------------------------------------------------------------

/// Decide se um novo respawn é permitido dado o histórico na janela.
fn respawn_allowed(history: &[Instant], now: Instant, max: u32, window: Duration) -> bool {
    let recent = history
        .iter()
        .filter(|t| now.duration_since(**t) < window)
        .count();
    recent < max as usize
}

// ---------------------------------------------------------------------------
// Daemon: processo filho persistente (async)
// ---------------------------------------------------------------------------

struct Daemon {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
}

impl Daemon {
    /// Spawn genérico (testável com processos fake). Se `wait_ready`, espera a
    /// linha `{"ready":true,...}` com timeout de partida.
    async fn spawn_generic(
        program: &str,
        args: &[String],
        stderr_log: &Path,
        wait_ready: bool,
        ready_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let err_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(stderr_log)
            .with_context(|| format!("abrindo log do daemon {}", stderr_log.display()))?;
        let mut child = Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::from(err_file))
            .spawn()
            .with_context(|| format!("spawn do daemon em {program}"))?;
        let stdin = child.stdin.take().context("stdin do daemon")?;
        let stdout = child.stdout.take().context("stdout do daemon")?;
        let mut d = Daemon {
            child,
            stdin,
            reader: BufReader::new(stdout),
        };
        if wait_ready {
            let mut line = match timeout(ready_timeout, d.read_line()).await {
                Ok(r) => r.context("lendo prontidão do daemon")?,
                Err(_) => bail!("timeout de partida do daemon ({ready_timeout:?})"),
            };
            let v: serde_json::Value = serde_json::from_str(&line)
                .context("parseando prontidão do daemon")
                .inspect(|_| line.zeroize())?;
            line.zeroize();
            if v.get("ready").and_then(|r| r.as_bool()) != Some(true) {
                let err = v
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("desconhecido");
                bail!("daemon não ficou pronto: {}", sanitize_daemon_error(err));
            }
        }
        Ok(d)
    }

    async fn spawn_real(cfg: &Config) -> anyhow::Result<Self> {
        let script = daemon_script(cfg);
        let stderr_log = cfg.audit_log.with_file_name("vault-daemon.log");
        let args = vec![
            "-NoProfile".to_string(),
            "-File".to_string(),
            script.to_string_lossy().into_owned(),
            "-DocPath".to_string(),
            cfg.document_path.to_string_lossy().into_owned(),
        ];
        Self::spawn_generic(
            &cfg.pwsh_path.to_string_lossy(),
            &args,
            &stderr_log,
            true,
            READY_TIMEOUT,
        )
        .await
    }

    async fn read_line(&mut self) -> anyhow::Result<String> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .await
            .context("lendo resposta do daemon")?;
        if n == 0 {
            bail!("daemon fechou o stdout (morreu?)");
        }
        Ok(line)
    }

    /// Envia um pedido e lê a resposta com timeout. Falhas são classificadas:
    /// Timeout/Transport/Protocol (respawn) vs Business (erro JSON do daemon).
    async fn request(
        &mut self,
        req: &serde_json::Value,
        req_timeout: Duration,
    ) -> Result<String, (DaemonFailure, String)> {
        let mut payload = serde_json::to_string(req)
            .map_err(|e| (DaemonFailure::Protocol, format!("serializando pedido: {e}")))?;
        payload.push('\n');

        let io = async {
            self.stdin
                .write_all(payload.as_bytes())
                .await
                .context("escrevendo pedido ao daemon")?;
            self.stdin.flush().await.context("flush do pedido")?;
            self.read_line().await
        };

        match timeout(req_timeout, io).await {
            Err(_) => Err((
                DaemonFailure::Timeout,
                format!("daemon não respondeu em {req_timeout:?}"),
            )),
            Ok(Err(e)) => Err((DaemonFailure::Transport, format!("{e:#}"))),
            Ok(Ok(line)) => {
                // Pré-valida o protocolo: JSON inválido desalinha tudo (respawn);
                // {"error": ...} é erro de negócio do daemon (NÃO respawna).
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(v) => {
                        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                            Err((
                                DaemonFailure::Business,
                                format!(
                                    "resolução de credencial falhou: {}",
                                    sanitize_daemon_error(err)
                                ),
                            ))
                        } else {
                            Ok(line)
                        }
                    }
                    Err(_) => Err((
                        DaemonFailure::Protocol,
                        "resposta do daemon não é JSON do protocolo".to_string(),
                    )),
                }
            }
        }
    }

    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    async fn kill(&mut self) {
        let _ = self.child.kill().await;
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

// ---------------------------------------------------------------------------
// Singleton + gerenciamento de ciclo de vida
// ---------------------------------------------------------------------------

struct DaemonCell {
    daemon: Option<Daemon>,
    respawns: Vec<Instant>,
}

static DAEMON: OnceCell<Arc<Mutex<DaemonCell>>> = OnceCell::const_new();

async fn daemon_cell() -> Arc<Mutex<DaemonCell>> {
    DAEMON
        .get_or_init(|| async {
            Arc::new(Mutex::new(DaemonCell {
                daemon: None,
                respawns: Vec::new(),
            }))
        })
        .await
        .clone()
}

/// O script do daemon mora ao lado do `resolve.ps1` (mesma pasta `ps/`).
fn daemon_script(cfg: &Config) -> PathBuf {
    cfg.resolve_script.with_file_name("vault-daemon.ps1")
}

/// Futuro de uma operação sobre o daemon (empréstimo do &mut Daemon).
type DaemonOp<'a, T> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<T, (DaemonFailure, String)>> + Send + 'a>,
>;

/// Garante um daemon vivo e executa `op`. Em falha classificada como
/// Timeout/Transport/Protocol: descarta, respawna (se o circuit breaker
/// permitir) e retenta UMA vez.
async fn with_daemon<T>(
    cfg: &Config,
    op: impl for<'a> Fn(&'a mut Daemon) -> DaemonOp<'a, T>,
) -> Result<T, String> {
    let cell = daemon_cell().await;
    let mut guard = cell.lock().await;

    // Garante vivo (respawn sob demanda).
    let alive = match guard.daemon.as_mut() {
        Some(d) => d.is_alive(),
        None => false,
    };
    if !alive {
        if let Some(mut d) = guard.daemon.take() {
            tracing::warn!("daemon do vault morreu; respawnando");
            d.kill().await;
        }
        ensure_respawn_budget(&mut guard)?;
        guard.daemon = Some(
            Daemon::spawn_real(cfg)
                .await
                .map_err(|e| format!("spawn do daemon falhou: {e:#}"))?,
        );
    }

    let d = guard.daemon.as_mut().expect("daemon garantido vivo");
    match op(d).await {
        Ok(v) => Ok(v),
        Err((kind, msg)) if classify_line_failure(&kind) => {
            tracing::warn!(?kind, error = %msg, "falha de daemon; respawn + 1 retentativa");
            if let Some(mut old) = guard.daemon.take() {
                old.kill().await;
            }
            ensure_respawn_budget(&mut guard)?;
            let mut d2 = Daemon::spawn_real(cfg)
                .await
                .map_err(|e| format!("respawn do daemon falhou: {e:#}"))?;
            let r = op(&mut d2).await.map_err(|(kind2, msg2)| {
                format!("falha também na retentativa ({kind2:?}): {msg2}")
            });
            guard.daemon = Some(d2);
            r
        }
        Err((_, msg)) => Err(msg),
    }
}

/// Circuit breaker: limita respawns por janela (respawn custa 15-20s de pwsh).
fn ensure_respawn_budget(cell: &mut DaemonCell) -> Result<(), String> {
    let now = Instant::now();
    cell.respawns
        .retain(|t| now.duration_since(*t) < RESPAWN_WINDOW);
    if !respawn_allowed(&cell.respawns, now, MAX_RESPAWNS, RESPAWN_WINDOW) {
        return Err(format!(
            "circuit breaker: mais de {MAX_RESPAWNS} respawns do daemon em {}s — verifique vault-daemon.log",
            RESPAWN_WINDOW.as_secs()
        ));
    }
    cell.respawns.push(now);
    Ok(())
}

// ---------------------------------------------------------------------------
// Protocolo (funções puras — seam de teste unitário)
// ---------------------------------------------------------------------------

fn build_resolve_request(host_id: &str) -> serde_json::Value {
    serde_json::json!({ "cmd": "resolve", "host_id": host_id })
}

fn build_reload_request() -> serde_json::Value {
    serde_json::json!({ "cmd": "reload" })
}

/// Parseia a resposta de um `resolve`. A string de entrada contém o segredo em
/// claro; o chamador DEVE zeroizá-la após o parse (os campos movem-se para
/// `Secret`, que zeroiza no drop). Erros de negócio do daemon são sanitizados.
fn parse_resolve_response(line: &str) -> anyhow::Result<ResolveRaw> {
    let v: serde_json::Value =
        serde_json::from_str(line).context("parseando JSON da credencial")?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        bail!(
            "resolução de credencial falhou: {}",
            sanitize_daemon_error(err)
        );
    }
    let raw: ResolveRaw = serde_json::from_value(v).context("parseando JSON da credencial")?;
    Ok(raw)
}

// ---------------------------------------------------------------------------
// API pública (async; contrato de saída inalterado)
// ---------------------------------------------------------------------------

/// Resolve a credencial de um host por ID via daemon. `host_id` deve já ter
/// passado pela checagem de escopo do chamador.
pub async fn resolve(cfg: &Config, host_id: &str) -> anyhow::Result<ResolvedCredential> {
    let req = build_resolve_request(host_id);
    let mut line = with_daemon(cfg, |d| {
        let req = req.clone();
        Box::pin(async move { d.request(&req, REQUEST_TIMEOUT).await })
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?;

    let raw = parse_resolve_response(&line).inspect(|_| line.zeroize())?;
    line.zeroize();

    let auth = match raw.auth.as_str() {
        "password" => AuthMaterial::Password(Secret::new(raw.password.unwrap_or_default())),
        "key" => AuthMaterial::Key {
            content: Secret::new(raw.key_content.unwrap_or_default()),
            passphrase: raw.passphrase.filter(|s| !s.is_empty()).map(Secret::new),
        },
        _ => AuthMaterial::None,
    };

    Ok(ResolvedCredential {
        username: raw.username,
        auth,
        stale: raw.stale,
    })
}

/// Força a reabertura do documento no daemon (hook de `refresh_inventory`,
/// ADR-0002). Retorna o total de hosts SSH no documento reaberto.
pub async fn reload(cfg: &Config) -> anyhow::Result<u64> {
    let req = build_reload_request();
    let line = with_daemon(cfg, |d| {
        let req = req.clone();
        Box::pin(async move { d.request(&req, REQUEST_TIMEOUT).await })
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?;
    let v: serde_json::Value = serde_json::from_str(&line).context("parseando reload")?;
    if v.get("ok").and_then(|o| o.as_bool()) == Some(true) {
        Ok(v.get("hosts").and_then(|h| h.as_u64()).unwrap_or(0))
    } else {
        let err = v
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("desconhecido");
        bail!("reload do daemon falhou: {}", sanitize_daemon_error(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- protocolo ----

    #[test]
    fn request_de_resolve_tem_formato_do_protocolo() {
        let v = build_resolve_request("abc-123");
        assert_eq!(v["cmd"], "resolve");
        assert_eq!(v["host_id"], "abc-123");
    }

    #[test]
    fn request_de_reload_tem_formato_do_protocolo() {
        assert_eq!(build_reload_request()["cmd"], "reload");
    }

    #[test]
    fn parse_resposta_password_ok() {
        let raw = parse_resolve_response(
            r#"{"username":"svc.flowbix","auth":"password","password":"segredo123","key_content":null,"passphrase":null,"stale":false}"#,
        )
        .unwrap();
        assert_eq!(raw.username, "svc.flowbix");
        assert_eq!(raw.auth, "password");
        assert_eq!(raw.password.as_deref(), Some("segredo123"));
        assert!(!raw.stale);
    }

    #[test]
    fn parse_resposta_key_com_stale() {
        let raw = parse_resolve_response(
            r#"{"username":"root","auth":"key","password":null,"key_content":"-----BEGIN","passphrase":"p","stale":true}"#,
        )
        .unwrap();
        assert_eq!(raw.auth, "key");
        assert_eq!(raw.key_content.as_deref(), Some("-----BEGIN"));
        assert_eq!(raw.passphrase.as_deref(), Some("p"));
        assert!(raw.stale);
    }

    #[test]
    fn parse_resposta_de_erro_vira_err_sanitizado() {
        let r = parse_resolve_response(r#"{"error":"host nao encontrado: xyz"}"#);
        let msg = format!("{}", r.err().unwrap());
        assert!(msg.contains("host nao encontrado"), "msg={msg}");
    }

    #[test]
    fn parse_json_quebrado_vira_err() {
        assert!(parse_resolve_response("{nao e json").is_err());
    }

    // ---- sanitização ----

    #[test]
    fn sanitize_remove_quebras_de_linha() {
        let s = sanitize_daemon_error("linha1\nlinha2\r\nlinha3");
        assert_eq!(s, "linha1 linha2 linha3");
    }

    #[test]
    fn sanitize_trunca_mensagens_longas() {
        let long = "x".repeat(500);
        let s = sanitize_daemon_error(&long);
        assert!(s.chars().count() <= MAX_ERROR_LEN + 1);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn sanitize_preserva_mensagem_curta() {
        assert_eq!(sanitize_daemon_error("  erro curto  "), "erro curto");
    }

    // ---- classificação de falhas ----

    #[test]
    fn timeout_transport_protocol_respawnam_business_nao() {
        assert!(classify_line_failure(&DaemonFailure::Timeout));
        assert!(classify_line_failure(&DaemonFailure::Transport));
        assert!(classify_line_failure(&DaemonFailure::Protocol));
        assert!(!classify_line_failure(&DaemonFailure::Business));
    }

    // ---- circuit breaker ----

    #[test]
    fn circuit_breaker_permite_ate_o_teto_na_janela() {
        let now = Instant::now();
        let history = vec![now - Duration::from_secs(10), now - Duration::from_secs(20)];
        assert!(respawn_allowed(&history, now, 3, Duration::from_secs(300)));
        let full = vec![
            now - Duration::from_secs(10),
            now - Duration::from_secs(20),
            now - Duration::from_secs(30),
        ];
        assert!(!respawn_allowed(&full, now, 3, Duration::from_secs(300)));
        // Respawns antigos (fora da janela) não contam.
        let old = vec![
            now - Duration::from_secs(600),
            now - Duration::from_secs(700),
            now - Duration::from_secs(800),
        ];
        assert!(respawn_allowed(&old, now, 3, Duration::from_secs(300)));
    }

    // ---- daemon com processos fake ----

    fn fake_stderr_log() -> PathBuf {
        std::env::temp_dir().join(format!("vault-test-{}.log", std::process::id()))
    }

    #[tokio::test]
    async fn request_em_daemon_travado_estoura_timeout() {
        // Processo que nunca responde: sleep puro.
        let args = vec!["60".to_string()];
        let mut d = Daemon::spawn_generic("sleep", &args, &fake_stderr_log(), false, READY_TIMEOUT)
            .await
            .expect("spawn sleep");
        let req = serde_json::json!({"cmd":"ping"});
        let err = d
            .request(&req, Duration::from_millis(300))
            .await
            .expect_err("deve falhar");
        assert_eq!(err.0, DaemonFailure::Timeout);
        d.kill().await;
    }

    #[tokio::test]
    async fn resposta_nao_json_classifica_como_protocolo() {
        // Processo que responde lixo e segue vivo.
        let args = vec![
            "-c".to_string(),
            "echo 'isto nao e json'; sleep 60".to_string(),
        ];
        let mut d = Daemon::spawn_generic("sh", &args, &fake_stderr_log(), false, READY_TIMEOUT)
            .await
            .expect("spawn sh");
        let req = serde_json::json!({"cmd":"ping"});
        let err = d
            .request(&req, Duration::from_secs(5))
            .await
            .expect_err("deve falhar");
        assert_eq!(err.0, DaemonFailure::Protocol);
        d.kill().await;
    }

    #[tokio::test]
    async fn processo_morto_classifica_como_transporte() {
        // Processo que sai imediatamente: EOF no stdout.
        let args = vec!["-c".to_string(), "exit 0".to_string()];
        let mut d = Daemon::spawn_generic("sh", &args, &fake_stderr_log(), false, READY_TIMEOUT)
            .await
            .expect("spawn sh");
        let req = serde_json::json!({"cmd":"ping"});
        let err = d
            .request(&req, Duration::from_secs(5))
            .await
            .expect_err("deve falhar");
        assert_eq!(err.0, DaemonFailure::Transport);
        d.kill().await;
    }

    #[tokio::test]
    async fn daemon_funcional_responde_linha_json() {
        // Fake que se comporta como o daemon real para 1 pedido.
        let args = vec![
            "-c".to_string(),
            "read line; echo '{\"ok\":true}'; sleep 60".to_string(),
        ];
        let mut d = Daemon::spawn_generic("sh", &args, &fake_stderr_log(), false, READY_TIMEOUT)
            .await
            .expect("spawn sh");
        let req = serde_json::json!({"cmd":"ping"});
        let line = d
            .request(&req, Duration::from_secs(5))
            .await
            .expect("resposta ok");
        assert!(line.contains("\"ok\":true"));
        d.kill().await;
    }
}
