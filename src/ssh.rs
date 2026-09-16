//! Motor SSH (russh) com **pool multiplexado por host** (ADR-0003): uma
//! conexão por host, canais sob demanda, expiração por ociosidade (~75s),
//! reconexão transparente quando a conexão morre e UM retry com backoff em
//! timeout de conexão. Auth por senha OU chave, cap de output configurável,
//! pinning de host key (known_hosts) e operações de arquivo via SFTP.
//!
//! Segurança de host key: TOFU **persistente** (por conexão, inalterado). Na
//! primeira conexão a fingerprint é gravada em `known_hosts`; nas seguintes é
//! exigida igualdade — divergência (possível MITM) **recusa** a conexão.
use crate::config::Config;
use crate::vault::{AuthMaterial, ResolvedCredential};
use anyhow::{Context, bail};
use russh::ChannelMsg;
use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, decode_secret_key};
use russh_sftp::protocol::OpenFlags;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout};
use zeroize::Zeroize;

/// Serializa o par lookup+append no known_hosts entre conexões concorrentes,
/// evitando linhas duplicadas / decisão sobre estado inconsistente (TOFU).
static KNOWN_HOSTS_LOCK: Mutex<()> = Mutex::new(());

/// Conexão ociosa expira e é refeita sob demanda (ADR-0003).
const IDLE_TTL: Duration = Duration::from_secs(75);
/// Teto de canais concorrentes por host — abaixo do `MaxSessions` default (10)
/// do OpenSSH, deixando margem para sessões interativas do dono.
const MAX_CHANNELS_PER_HOST: usize = 8;
/// Backoff do retry único em timeout de conexão (ADR-0003).
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Parâmetros de transporte derivados do `Config` (sem segredo).
#[derive(Clone)]
pub struct SshSettings {
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub output_cap: usize,
    pub known_hosts: PathBuf,
}

impl SshSettings {
    pub fn from_config(cfg: &Config) -> Self {
        SshSettings {
            connect_timeout: cfg.limits.connect_timeout(),
            command_timeout: cfg.limits.command_timeout(),
            output_cap: cfg.limits.output_cap_bytes,
            known_hosts: cfg.known_hosts.clone(),
        }
    }
}

/// Modo de escrita do `file_put` (ADR-0004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Só cria arquivo NOVO (`O_EXCL`); falha se existir. Default anti-acidente.
    Create,
    /// Sobrescreve (trunca) arquivo existente. Exige Aprovação no servidor.
    Overwrite,
    /// Anexa ao final de arquivo existente (cria se não existir). Exige Aprovação.
    Append,
}

impl WriteMode {
    fn flags(self) -> OpenFlags {
        match self {
            WriteMode::Create => OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::EXCLUDE,
            WriteMode::Overwrite => OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            WriteMode::Append => OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::APPEND,
        }
    }
}

pub struct ExecOutcome {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<u32>,
    pub truncated: bool,
}

/// Resultado de leitura de arquivo (SFTP).
pub struct FileContent {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// Handler com pinning de host key persistente.
struct Handler {
    known_hosts: PathBuf,
    host_label: String,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        // Lock síncrono: não há `.await` enquanto segurado (lookup/append são fs sync).
        let _guard = KNOWN_HOSTS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match known_hosts_lookup(&self.known_hosts, &self.host_label) {
            Some(stored) if stored == fp => {
                tracing::debug!(host = %self.host_label, "host key confere com known_hosts");
                Ok(true)
            }
            Some(stored) => {
                tracing::error!(
                    host = %self.host_label, esperado = %stored, recebido = %fp,
                    "HOST KEY DIVERGENTE — possível MITM; recusando conexão"
                );
                Ok(false)
            }
            None => {
                // TOFU fail-CLOSED (T5): se o pin não puder ser persistido, a
                // conexão é recusada. Aceitar sem gravar deixaria o host
                // permanentemente em "primeira conexão" — janela de MITM
                // contínua e silenciosa.
                if let Err(e) = known_hosts_append(&self.known_hosts, &self.host_label, &fp) {
                    tracing::error!(
                        host = %self.host_label, error = %e,
                        "falha ao gravar known_hosts — recusando conexão (TOFU fail-closed)"
                    );
                    return Ok(false);
                }
                tracing::warn!(host = %self.host_label, fingerprint = %fp, "host key novo: pinned (TOFU)");
                Ok(true)
            }
        }
    }
}

/// Procura a fingerprint pinada para `label` no known_hosts. Formato por linha:
/// `<host>:<port> SHA256:....`.
fn known_hosts_lookup(path: &PathBuf, label: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((h, fp)) = line.split_once(char::is_whitespace)
            && h == label
        {
            return Some(fp.trim().to_string());
        }
    }
    None
}

fn known_hosts_append(path: &PathBuf, label: &str, fp: &str) -> anyhow::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("abrindo known_hosts {}", path.display()))?;
    writeln!(f, "{label} {fp}")?;
    Ok(())
}

/// Conecta e autentica, devolvendo o handle pronto para abrir canais.
async fn connect_and_auth(
    settings: &SshSettings,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
) -> anyhow::Result<client::Handle<Handler>> {
    let config = Arc::new(client::Config::default());
    let handler = Handler {
        known_hosts: settings.known_hosts.clone(),
        host_label: format!("{addr}:{port}"),
    };

    let mut handle = timeout(
        settings.connect_timeout,
        client::connect(config, (addr, port), handler),
    )
    .await
    .context("timeout de conexão SSH")?
    .context("falha ao conectar via SSH (host key recusada?)")?;

    match &cred.auth {
        AuthMaterial::Password(p) => {
            let res = timeout(
                settings.connect_timeout,
                handle.authenticate_password(&cred.username, p.expose()),
            )
            .await
            .context("timeout na autenticação por senha")?
            .context("erro durante autenticação por senha")?;
            if !res.success() {
                bail!("autenticação por senha rejeitada para {}", cred.username);
            }
        }
        AuthMaterial::Key {
            content,
            passphrase,
        } => {
            let pass = passphrase.as_ref().map(|p| p.expose());
            let key = decode_secret_key(content.expose(), pass)
                .context("decodificando chave privada SSH")?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
            let res = timeout(
                settings.connect_timeout,
                handle.authenticate_publickey(&cred.username, key),
            )
            .await
            .context("timeout na autenticação por chave")?
            .context("erro durante autenticação por chave")?;
            if !res.success() {
                bail!("autenticação por chave rejeitada para {}", cred.username);
            }
        }
        AuthMaterial::None => bail!("host sem credencial resolvível"),
    }

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Pool multiplexado por host (ADR-0003)
// ---------------------------------------------------------------------------

/// Conexão quente de um host: handle russh + semáforo de canais + last-used.
struct PooledConn {
    handle: client::Handle<Handler>,
    channels: Arc<Semaphore>,
    last_used: Mutex<Instant>,
}

impl PooledConn {
    fn touch(&self) {
        *self.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
    }
}

/// Pool de conexões SSH: uma por host (`addr:port`), canais multiplexados.
/// Conexões ociosas além de `IDLE_TTL` são fechadas pelo reaper periódico
/// (não só lazy no próximo acesso — T2). Connects concorrentes ao mesmo host
/// compartilham UMA tentativa (single-flight por host).
pub struct SshPool {
    settings: SshSettings,
    conns: Arc<Mutex<HashMap<String, Arc<PooledConn>>>>,
    /// Single-flight: um connect por host por vez (T2).
    connect_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Reaper de conexões ociosas (abortado no drop do pool).
    reaper: Mutex<Option<tokio::task::AbortHandle>>,
}

impl SshPool {
    pub fn new(settings: SshSettings) -> Self {
        let pool = SshPool {
            settings,
            conns: Arc::new(Mutex::new(HashMap::new())),
            connect_locks: Mutex::new(HashMap::new()),
            reaper: Mutex::new(None),
        };
        // O reaper precisa de runtime tokio; fora dele (testes unitários de
        // helpers), o pool funciona sem reaper.
        if tokio::runtime::Handle::try_current().is_ok() {
            let conns = pool.conns.clone();
            let task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                interval.tick().await; // primeira marcação é imediata; pula
                loop {
                    interval.tick().await;
                    let mut m = conns.lock().unwrap_or_else(|e| e.into_inner());
                    let stale: Vec<String> = m
                        .iter()
                        .filter(|(_, p)| p.idle_for() >= IDLE_TTL)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for k in stale {
                        tracing::debug!(host = %k, "conexão ociosa fechada pelo reaper");
                        m.remove(&k);
                    }
                }
            });
            *pool.reaper.lock().unwrap_or_else(|e| e.into_inner()) = Some(task.abort_handle());
        }
        pool
    }

    pub fn settings(&self) -> &SshSettings {
        &self.settings
    }

    fn key(addr: &str, port: u16) -> String {
        format!("{addr}:{port}")
    }

    fn cached(&self, key: &str) -> Option<Arc<PooledConn>> {
        let map = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(key) {
            Some(p) if p.idle_for() < IDLE_TTL => Some(p.clone()),
            _ => None,
        }
    }

    fn insert(&self, key: String, conn: Arc<PooledConn>) {
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, conn);
    }

    /// Remove a entrada SOMENTE se for a mesma instância que falhou (T2):
    /// evita remover a conexão nova e saudável que outra task acabou de
    /// reconectar. Genérica para ser testável sem russh.
    fn remove_if_same<T>(map: &Mutex<HashMap<String, Arc<T>>>, key: &str, conn: &Arc<T>) -> bool {
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        match m.get(key) {
            Some(current) if Arc::ptr_eq(current, conn) => {
                m.remove(key);
                true
            }
            _ => false,
        }
    }

    /// Conecta (com UM retry em timeout) e registra no pool.
    async fn connect(
        &self,
        addr: &str,
        port: u16,
        cred: &ResolvedCredential,
    ) -> anyhow::Result<Arc<PooledConn>> {
        let key = Self::key(addr, port);
        let handle = match connect_and_auth(&self.settings, addr, port, cred).await {
            Ok(h) => h,
            Err(e) => {
                if !is_connect_timeout(&e) {
                    return Err(e);
                }
                tracing::warn!(host = %key, "timeout de conexão; retentando após backoff");
                sleep(CONNECT_RETRY_BACKOFF).await;
                connect_and_auth(&self.settings, addr, port, cred).await?
            }
        };
        let conn = Arc::new(PooledConn {
            handle,
            channels: Arc::new(Semaphore::new(MAX_CHANNELS_PER_HOST)),
            last_used: Mutex::new(Instant::now()),
        });
        self.insert(key, conn.clone());
        Ok(conn)
    }

    /// Devolve uma conexão quente do pool (ou conecta). Single-flight: N tasks
    /// concorrentes no mesmo host frio resultam em UM connect (T2).
    async fn conn(
        &self,
        addr: &str,
        port: u16,
        cred: &ResolvedCredential,
    ) -> anyhow::Result<Arc<PooledConn>> {
        let key = Self::key(addr, port);
        if let Some(p) = self.cached(&key) {
            return Ok(p);
        }
        let host_lock = self
            .connect_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = host_lock.lock().await;
        // Outra task pode ter conectado enquanto esperávamos o lock.
        if let Some(p) = self.cached(&key) {
            return Ok(p);
        }
        let conn = self.connect(addr, port, cred).await?;
        // Limpa a entrada do lock se ninguém mais espera por ela.
        if Arc::strong_count(&host_lock) == 2 {
            self.connect_locks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }
        Ok(conn)
    }

    /// Abre um canal de sessão na conexão do host. Se a conexão morreu (VPN
    /// caiu, host reiniciou), descarta APENAS se a entrada atual for a mesma
    /// instância, reconecta transparentemente UMA vez e tenta de novo
    /// (ADR-0003/T2). O permit limita canais concorrentes por host.
    async fn open_session_channel(
        &self,
        addr: &str,
        port: u16,
        cred: &ResolvedCredential,
    ) -> anyhow::Result<(
        russh::Channel<client::Msg>,
        OwnedSemaphorePermit,
        Arc<PooledConn>,
    )> {
        let conn = self.conn(addr, port, cred).await?;
        let permit = conn
            .channels
            .clone()
            .acquire_owned()
            .await
            .context("semáforo de canais fechado")?;
        match timeout(
            self.settings.connect_timeout,
            conn.handle.channel_open_session(),
        )
        .await
        {
            Ok(Ok(ch)) => {
                conn.touch();
                Ok((ch, permit, conn))
            }
            Ok(Err(e)) => {
                drop(permit);
                tracing::warn!(host = %Self::key(addr, port), error = %e, "canal falhou; reconectando");
                Self::remove_if_same(&self.conns, &Self::key(addr, port), &conn);
                let conn2 = self.connect(addr, port, cred).await?;
                let permit2 = conn2
                    .channels
                    .clone()
                    .acquire_owned()
                    .await
                    .context("semáforo de canais fechado")?;
                let ch = timeout(
                    self.settings.connect_timeout,
                    conn2.handle.channel_open_session(),
                )
                .await
                .context("timeout abrindo canal SSH (após reconexão)")?
                .context("abrindo canal SSH (após reconexão)")?;
                conn2.touch();
                Ok((ch, permit2, conn2))
            }
            Err(_) => {
                drop(permit);
                Self::remove_if_same(&self.conns, &Self::key(addr, port), &conn);
                Err(anyhow::anyhow!("timeout abrindo canal SSH"))
            }
        }
    }
}

impl Drop for SshPool {
    fn drop(&mut self) {
        if let Some(h) = self.reaper.lock().unwrap_or_else(|e| e.into_inner()).take() {
            h.abort();
        }
    }
}

/// True se a cadeia de erro tem um timeout de conexão (Elapsed). Substitui o
/// string-matching frágil (T2/M1).
fn is_connect_timeout(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<tokio::time::error::Elapsed>())
}

// ---------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------

/// Executa um comando via SSH. Quando `sudo_password` é `Some` e o comando usa
/// `sudo`/`doas` em posição de comando, o comando é reescrito para `sudo -S -p ''`
/// e a senha é injetada no stdin do canal — assim `sudo` funciona sem TTY e sem
/// `NOPASSWD`. A senha NUNCA é logada nem retornada (só transita pelo stdin do
/// canal e é zerada do buffer local após o envio).
pub async fn exec(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    command: &str,
    sudo_password: Option<&str>,
) -> anyhow::Result<ExecOutcome> {
    let (channel, _permit, conn) = pool.open_session_channel(addr, port, cred).await?;
    let mut channel = channel;

    // Só injeta a senha quando o comando FINAL realmente contém `sudo -S`
    // (reescrito por nós ou explícito). Ver `policy::prepare_sudo_exec` — sem
    // isso, a senha podia vazar pelo stdout em comandos com pipe/`sudo -n`.
    let (final_cmd, feed) = crate::policy::prepare_sudo_exec(command, sudo_password.is_some());
    let feed_password = if feed { sudo_password } else { None };

    channel
        .exec(true, final_cmd.as_str())
        .await
        .context("disparando exec")?;

    if let Some(pw) = feed_password {
        let mut data = pw.as_bytes().to_vec();
        data.push(b'\n');
        // Envia a senha no stdin do canal (sudo -S). Ignora erro: em host
        // NOPASSWD o sudo pode fechar o stdin antes de consumir.
        let _ = channel.data(&data[..]).await;
        data.zeroize();
        let _ = channel.eof().await;
    }

    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut exit_code = None;
    let mut truncated = false;
    let cap = pool.settings().output_cap;

    let read_loop = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    push_capped(&mut stdout, data, cap, &mut truncated)
                }
                ChannelMsg::ExtendedData { ref data, ext: _ } => {
                    push_capped(&mut stderr, data, cap, &mut truncated)
                }
                ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                _ => {}
            }
        }
    };
    timeout(pool.settings().command_timeout, read_loop)
        .await
        .context("timeout de execução do comando")?;

    conn.touch();
    Ok(ExecOutcome {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code,
        truncated,
    })
}

// ---------------------------------------------------------------------------
// SFTP
// ---------------------------------------------------------------------------

/// Sessão SFTP que SEGURA o permit do semáforo e a conexão durante toda a
/// transferência (T2/A5): o teto de canais por host vale de verdade, não só
/// no setup. No drop, marca o último uso da conexão (idle TTL correto).
struct SftpLease {
    session: russh_sftp::client::SftpSession,
    _permit: OwnedSemaphorePermit,
    conn: Arc<PooledConn>,
}

impl Drop for SftpLease {
    fn drop(&mut self) {
        self.conn.touch();
    }
}

/// Abre uma sessão SFTP sobre um canal da conexão quente do host.
async fn open_sftp(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
) -> anyhow::Result<SftpLease> {
    let (channel, permit, conn) = pool.open_session_channel(addr, port, cred).await?;
    timeout(
        pool.settings().connect_timeout,
        channel.request_subsystem(true, "sftp"),
    )
    .await
    .context("timeout solicitando subsistema sftp")?
    .context("solicitando subsistema sftp")?;
    let session = timeout(
        pool.settings().connect_timeout,
        russh_sftp::client::SftpSession::new(channel.into_stream()),
    )
    .await
    .context("timeout iniciando sessão SFTP")?
    .context("iniciando sessão SFTP")?;
    Ok(SftpLease {
        session,
        _permit: permit,
        conn,
    })
}

/// Lê um arquivo via SFTP (com cap). Falha se não existir.
pub async fn file_get(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    path: &str,
    max_bytes: usize,
) -> anyhow::Result<FileContent> {
    let lease = open_sftp(pool, addr, port, cred).await?;
    // Leitura com cap por streaming: nunca aloca além de max_bytes+1, mesmo que o
    // arquivo remoto seja enorme (anti-OOM). Lê 1 byte extra só p/ detectar corte.
    let mut file = timeout(
        pool.settings().command_timeout,
        lease.session.open(path.to_string()),
    )
    .await
    .context("timeout abrindo arquivo remoto")?
    .with_context(|| format!("abrindo arquivo remoto {path}"))?;
    let limit = (max_bytes as u64).saturating_add(1);
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("lendo arquivo remoto {path}"))?;
    file.shutdown().await.ok();
    let truncated = bytes.len() > max_bytes;
    if truncated {
        bytes.truncate(max_bytes);
    }
    Ok(FileContent { bytes, truncated })
}

/// Escreve `data` em `path` conforme o `mode` (ADR-0004). Create falha se o
/// arquivo existir; Overwrite trunca; Append anexa ao final.
pub async fn file_put_mode(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    path: &str,
    data: &[u8],
    mode: WriteMode,
) -> anyhow::Result<()> {
    let lease = open_sftp(pool, addr, port, cred).await?;
    let mut file = timeout(
        pool.settings().command_timeout,
        lease
            .session
            .open_with_flags(path.to_string(), mode.flags()),
    )
    .await
    .context("timeout abrindo arquivo remoto para escrita")?
    .with_context(|| match mode {
        WriteMode::Create => format!("criando arquivo novo {path} (já existe?)"),
        WriteMode::Overwrite => format!("abrindo {path} para sobrescrita"),
        WriteMode::Append => format!("abrindo {path} para append"),
    })?;
    file.write_all(data)
        .await
        .with_context(|| format!("gravando em {path}"))?;
    // Propaga erro de close/flush: o SSH_FXP_CLOSE é a confirmação de gravação.
    file.shutdown()
        .await
        .with_context(|| format!("fechando arquivo remoto {path}"))?;
    Ok(())
}

/// Cria um arquivo NOVO via SFTP (atômico, create-new). Atalho de
/// `file_put_mode(.., Create)` — usado pelo CLI de diagnóstico.
pub async fn file_put_new(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    path: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    file_put_mode(pool, addr, port, cred, path, data, WriteMode::Create).await
}

/// Sobrescreve (trunca) um arquivo EXISTENTE via SFTP. Usado pelo `file_edit`,
/// que primeiro confirma existência e aplica o replace — sempre sob aprovação.
pub async fn file_overwrite(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    path: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    file_put_mode(pool, addr, port, cred, path, data, WriteMode::Overwrite).await
}

// ---------------------------------------------------------------------------
// Upload em chunks (ADR-0004): start/chunk/finish sobre arquivo temporário
// ---------------------------------------------------------------------------

/// Cria o arquivo temporário do upload (create-new; falha se colidir).
pub async fn upload_temp_create(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    temp_path: &str,
) -> anyhow::Result<()> {
    file_put_mode(pool, addr, port, cred, temp_path, b"", WriteMode::Create).await
}

/// Anexa um chunk ao arquivo temporário do upload.
pub async fn upload_temp_append(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    temp_path: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    file_put_mode(pool, addr, port, cred, temp_path, data, WriteMode::Append).await
}

/// Lê o arquivo temporário inteiro (para verificação de sha256 no finish).
pub async fn upload_temp_read(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    temp_path: &str,
) -> anyhow::Result<Vec<u8>> {
    let fc = file_get(pool, addr, port, cred, temp_path, usize::MAX - 1).await?;
    Ok(fc.bytes)
}

/// Verifica existência de um path remoto (metadata SFTP).
pub async fn remote_exists(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    path: &str,
) -> anyhow::Result<bool> {
    let lease = open_sftp(pool, addr, port, cred).await?;
    match timeout(
        pool.settings().command_timeout,
        lease.session.metadata(path.to_string()),
    )
    .await
    {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Err(anyhow::anyhow!("timeout em metadata remota")),
    }
}

/// Move (rename) o temporário para o destino final.
pub async fn remote_rename(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    from: &str,
    to: &str,
) -> anyhow::Result<()> {
    let lease = open_sftp(pool, addr, port, cred).await?;
    timeout(
        pool.settings().command_timeout,
        lease.session.rename(from.to_string(), to.to_string()),
    )
    .await
    .context("timeout movendo arquivo remoto")?
    .with_context(|| format!("movendo {from} para {to}"))?;
    Ok(())
}

/// Remove um arquivo remoto (cleanup de temporário; melhor esforço no chamador).
pub async fn remote_remove(
    pool: &SshPool,
    addr: &str,
    port: u16,
    cred: &ResolvedCredential,
    path: &str,
) -> anyhow::Result<()> {
    let lease = open_sftp(pool, addr, port, cred).await?;
    timeout(
        pool.settings().command_timeout,
        lease.session.remove_file(path.to_string()),
    )
    .await
    .context("timeout removendo arquivo remoto")?
    .with_context(|| format!("removendo {path}"))?;
    Ok(())
}

fn push_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize, truncated: &mut bool) {
    let remaining = cap.saturating_sub(buf.len());
    if remaining == 0 {
        *truncated = true;
        return;
    }
    let take = remaining.min(data.len());
    buf.extend_from_slice(&data[..take]);
    if take < data.len() {
        *truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_do_create_sao_exclusivas() {
        let f = WriteMode::Create.flags();
        assert!(f.contains(OpenFlags::CREATE));
        assert!(f.contains(OpenFlags::WRITE));
        assert!(f.contains(OpenFlags::EXCLUDE));
        assert!(!f.contains(OpenFlags::TRUNCATE));
        assert!(!f.contains(OpenFlags::APPEND));
    }

    #[test]
    fn flags_do_overwrite_truncam() {
        let f = WriteMode::Overwrite.flags();
        assert!(f.contains(OpenFlags::TRUNCATE));
        assert!(!f.contains(OpenFlags::EXCLUDE));
        assert!(!f.contains(OpenFlags::APPEND));
    }

    #[test]
    fn flags_do_append_anexam() {
        let f = WriteMode::Append.flags();
        assert!(f.contains(OpenFlags::APPEND));
        assert!(!f.contains(OpenFlags::EXCLUDE));
        assert!(!f.contains(OpenFlags::TRUNCATE));
    }

    #[test]
    fn push_capped_marca_truncamento() {
        let mut buf = Vec::new();
        let mut truncated = false;
        push_capped(&mut buf, b"abcdef", 4, &mut truncated);
        assert_eq!(buf, b"abcd");
        assert!(truncated);
    }

    // ---- T2: helpers do pool ----

    #[test]
    fn t2_remove_if_same_so_remove_a_mesma_instancia() {
        let map: Mutex<HashMap<String, Arc<i32>>> = Mutex::new(HashMap::new());
        let old = Arc::new(1);
        let new = Arc::new(2);
        map.lock().unwrap().insert("h".to_string(), new.clone());
        // A entrada atual é `new`; tentar remover pela `old` (falha) não remove.
        assert!(!SshPool::remove_if_same(&map, "h", &old));
        assert!(map.lock().unwrap().contains_key("h"));
        // Remover pela instância atual funciona.
        assert!(SshPool::remove_if_same(&map, "h", &new));
        assert!(map.lock().unwrap().get("h").is_none());
    }

    #[tokio::test]
    async fn t2_is_connect_timeout_detecta_elapsed_na_cadeia() {
        // Erro com Elapsed na cadeia (como o timeout() do connect produz).
        let elapsed = timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(5)).await
        })
        .await
        .unwrap_err();
        let wrapped = anyhow::Error::new(elapsed).context("timeout de conexão SSH");
        assert!(is_connect_timeout(&wrapped));

        // Erro comum (sem Elapsed) não é classificado como timeout.
        let other = anyhow::anyhow!("autenticação por senha rejeitada para root");
        assert!(!is_connect_timeout(&other));
    }
}
