//! MCP Royal — servidor MCP que é a fronteira de confiança para SSH/SFTP a
//! partir do inventário local do Royal TS/TSX (`.rtsz`).
//!
//! Uso:
//!   royal-mcp                          → serve o MCP via stdio
//!   royal-mcp dump-inventory           → imprime os hosts visíveis (diagnóstico)
//!   royal-mcp resolve <host>           → testa o vault (só metadados do segredo)
//!   royal-mcp ssh-test <host> <cmd...> → executa um comando via SSH (diagnóstico)
//!   royal-mcp file-get <host> <path>   → lê um arquivo via SFTP (diagnóstico)
//!   royal-mcp file-overwrite <host> <path> <arquivo-local> → sobrescreve via SFTP (diagnóstico)
//!
//! Config em `config.toml` (override por env `ROYAL_MCP_CONFIG`).
mod audit;
mod config;
mod inventory;
mod model;
mod policy;
mod ratelimit;
mod royal;
mod secret;
mod server;
mod ssh;
mod vault;

use anyhow::Context;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs SEMPRE em stderr — stdout é o canal JSON-RPC do MCP.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let config_path =
        std::env::var("ROYAL_MCP_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let cfg = config::Config::load(std::path::Path::new(&config_path))
        .with_context(|| format!("carregando config {config_path}"))?;

    let inv = inventory::Inventory::load(&cfg).context("carregando inventário via pwsh")?;
    tracing::info!(
        total = inv.total(),
        visible = inv.visible_count(),
        "inventário carregado"
    );

    // Subcomando de diagnóstico: imprime os hosts visíveis e sai (sem subir o MCP).
    if std::env::args().nth(1).as_deref() == Some("dump-inventory") {
        let hosts = inv.query(None, None);
        println!("{}", serde_json::to_string_pretty(&hosts)?);
        return Ok(());
    }

    // Subcomando de teste do Vault: resolve a credencial de um host (do escopo)
    // e imprime APENAS metadados — username, tipo de auth e o COMPRIMENTO do
    // segredo. Jamais o valor. Uso: royal-mcp resolve <nome-do-host>
    if std::env::args().nth(1).as_deref() == Some("resolve") {
        let name = std::env::args()
            .nth(2)
            .context("uso: resolve <nome-do-host>")?;
        let host = match inv.resolve(&name) {
            inventory::HostResolution::Found(h) => h,
            inventory::HostResolution::Ambiguous(c) => {
                anyhow::bail!("host '{name}' ambíguo: {} — use o ID", c.join(", "))
            }
            inventory::HostResolution::NotFound => {
                anyhow::bail!("host '{name}' não encontrado no escopo permitido")
            }
        };
        let cred = vault::resolve(&cfg, &host.id)
            .await
            .context("resolvendo credencial")?;
        let (kind, len) = match &cred.auth {
            vault::AuthMaterial::Password(s) => ("password", s.expose().len()),
            vault::AuthMaterial::Key { content, .. } => ("key", content.expose().len()),
            vault::AuthMaterial::None => ("none", 0),
        };
        println!(
            "host={} user={} auth={} secret_len={}",
            host.name, cred.username, kind, len
        );
        return Ok(());
    }

    // Subcomando de teste SSH: resolve credencial (escopo) e executa um comando.
    // Uso: royal-mcp ssh-test <nome-do-host> <comando...>
    if std::env::args().nth(1).as_deref() == Some("ssh-test") {
        let name = std::env::args()
            .nth(2)
            .context("uso: ssh-test <nome-do-host> <comando>")?;
        let command: String = std::env::args().skip(3).collect::<Vec<_>>().join(" ");
        if command.is_empty() {
            anyhow::bail!("uso: ssh-test <nome-do-host> <comando>");
        }
        let host = match inv.resolve(&name) {
            inventory::HostResolution::Found(h) => h,
            inventory::HostResolution::Ambiguous(c) => {
                anyhow::bail!("host '{name}' ambíguo: {} — use o ID", c.join(", "))
            }
            inventory::HostResolution::NotFound => {
                anyhow::bail!("host '{name}' não encontrado no escopo permitido")
            }
        };
        let cred = vault::resolve(&cfg, &host.id)
            .await
            .context("resolvendo credencial")?;
        let pool = ssh::SshPool::new(ssh::SshSettings::from_config(&cfg));
        tracing::info!(host = %host.name, uri = %host.uri, "conectando via SSH");
        let sudo_pw = match &cred.auth {
            vault::AuthMaterial::Password(s) => Some(s.expose()),
            _ => None,
        };
        let out = ssh::exec(&pool, &host.uri, host.port, &cred, &command, sudo_pw)
            .await
            .context("executando comando via SSH")?;
        println!(
            "--- exit: {:?}  truncated: {} ---",
            out.exit_code, out.truncated
        );
        println!("--- stdout ---\n{}", out.stdout);
        if !out.stderr.is_empty() {
            println!("--- stderr ---\n{}", out.stderr);
        }
        return Ok(());
    }

    // Subcomando de teste SFTP: lê um arquivo. Uso: royal-mcp file-get <host> <path>
    if std::env::args().nth(1).as_deref() == Some("file-get") {
        let name = std::env::args()
            .nth(2)
            .context("uso: file-get <nome-do-host> <path>")?;
        let path = std::env::args()
            .nth(3)
            .context("uso: file-get <nome-do-host> <path>")?;
        let host = match inv.resolve(&name) {
            inventory::HostResolution::Found(h) => h,
            inventory::HostResolution::Ambiguous(c) => {
                anyhow::bail!("host '{name}' ambíguo: {} — use o ID", c.join(", "))
            }
            inventory::HostResolution::NotFound => {
                anyhow::bail!("host '{name}' não encontrado no escopo permitido")
            }
        };
        let cred = vault::resolve(&cfg, &host.id)
            .await
            .context("resolvendo credencial")?;
        let pool = ssh::SshPool::new(ssh::SshSettings::from_config(&cfg));
        let fc = ssh::file_get(
            &pool,
            &host.uri,
            host.port,
            &cred,
            &path,
            cfg.files.max_get_bytes,
        )
        .await
        .context("lendo arquivo via SFTP")?;
        println!(
            "--- size: {}  truncated: {} ---",
            fc.bytes.len(),
            fc.truncated
        );
        println!("{}", String::from_utf8_lossy(&fc.bytes));
        return Ok(());
    }

    // Subcomando de teste SFTP de escrita (create-new). Uso:
    //   royal-mcp file-put <host> <path> <conteudo...>
    if std::env::args().nth(1).as_deref() == Some("file-put") {
        let name = std::env::args()
            .nth(2)
            .context("uso: file-put <host> <path> <conteudo>")?;
        let path = std::env::args()
            .nth(3)
            .context("uso: file-put <host> <path> <conteudo>")?;
        let content: String = std::env::args().skip(4).collect::<Vec<_>>().join(" ");
        let host = match inv.resolve(&name) {
            inventory::HostResolution::Found(h) => h,
            inventory::HostResolution::Ambiguous(c) => {
                anyhow::bail!("host '{name}' ambíguo: {} — use o ID", c.join(", "))
            }
            inventory::HostResolution::NotFound => {
                anyhow::bail!("host '{name}' não encontrado no escopo permitido")
            }
        };
        let cred = vault::resolve(&cfg, &host.id)
            .await
            .context("resolvendo credencial")?;
        let pool = ssh::SshPool::new(ssh::SshSettings::from_config(&cfg));
        ssh::file_put_new(
            &pool,
            &host.uri,
            host.port,
            &cred,
            &path,
            content.as_bytes(),
        )
        .await
        .context("criando arquivo via SFTP")?;
        println!("criado: {path} ({} bytes)", content.len());
        return Ok(());
    }

    // Subcomando de teste SFTP de sobrescrita. Uso:
    //   royal-mcp file-overwrite <host> <path-remoto> <arquivo-local>
    if std::env::args().nth(1).as_deref() == Some("file-overwrite") {
        let name = std::env::args()
            .nth(2)
            .context("uso: file-overwrite <host> <path-remoto> <arquivo-local>")?;
        let path = std::env::args()
            .nth(3)
            .context("uso: file-overwrite <host> <path-remoto> <arquivo-local>")?;
        let local = std::env::args()
            .nth(4)
            .context("uso: file-overwrite <host> <path-remoto> <arquivo-local>")?;
        let content =
            std::fs::read(&local).with_context(|| format!("lendo arquivo local {local}"))?;
        let host = match inv.resolve(&name) {
            inventory::HostResolution::Found(h) => h,
            inventory::HostResolution::Ambiguous(c) => {
                anyhow::bail!("host '{name}' ambíguo: {} — use o ID", c.join(", "))
            }
            inventory::HostResolution::NotFound => {
                anyhow::bail!("host '{name}' não encontrado no escopo permitido")
            }
        };
        let cred = vault::resolve(&cfg, &host.id)
            .await
            .context("resolvendo credencial")?;
        let pool = ssh::SshPool::new(ssh::SshSettings::from_config(&cfg));
        ssh::file_overwrite(&pool, &host.uri, host.port, &cred, &path, &content)
            .await
            .with_context(|| format!("sobrescrevendo {path} via SFTP"))?;
        println!("sobrescrito: {path} ({} bytes)", content.len());
        return Ok(());
    }

    let audit = audit::AuditLog::open(cfg.audit_log.clone()).context("abrindo audit log")?;
    let server = server::RoyalServer::new(inv, audit, cfg.clone());

    tracing::info!("servindo MCP via stdio");
    let service = server
        .serve(stdio())
        .await
        .context("iniciando serviço MCP")?;
    service.waiting().await?;
    Ok(())
}
