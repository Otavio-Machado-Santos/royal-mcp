//! Configuração do MCP, carregada de `config.toml`. Vive fora do alcance do agente.
//!
//! Paths relativos (scripts, audit log, known_hosts) são resolvidos contra o
//! diretório do próprio `config.toml` — assim o MCP roda de qualquer cwd (ex.:
//! lançado pelo Claude Code num projeto qualquer).
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub document_path: PathBuf,
    pub pwsh_path: PathBuf,
    pub inventory_script: PathBuf,
    pub resolve_script: PathBuf,
    pub audit_log: PathBuf,
    /// Arquivo known_hosts (pinning TOFU persistente). Default: `known_hosts`.
    #[serde(default = "default_known_hosts")]
    pub known_hosts: PathBuf,
    /// Como a aprovação humana das mutações (🟡) é obtida.
    #[serde(default)]
    pub approval_mode: ApprovalMode,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub files: Files,
}

/// Mecanismo de aprovação humana para operações que mudam estado (🟡).
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    /// (default) Servidor força um diálogo MCP elicitation. Exige cliente
    /// interativo capaz de renderizar (ex.: `claude` no terminal/TUI). Em
    /// clientes print-mode (ex.: app Claude Desktop) a elicitation é auto-negada.
    #[default]
    Elicitation,
    /// Sem gate server-side: o servidor EXECUTA a mutação confiando que o AGENTE
    /// obteve a aprovação humana antes (via AskUserQuestion no chat). Para
    /// ambientes onde a elicitation não renderiza. As travas DURAS (escopo,
    /// denylist de paths e comandos catastróficos) seguem ativas no servidor.
    Agent,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Scope {
    /// Allowlist de host por nome exato. Só estes entram no inventário visível.
    #[serde(default)]
    pub allow_host_names: Vec<String>,
    /// Allowlist por pasta/cliente (match no folder path, case-insensitive,
    /// por substring). Um host é visível se casar por nome OU por pasta.
    #[serde(default)]
    pub allow_folders: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Limits {
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_command_timeout")]
    pub command_timeout_secs: u64,
    #[serde(default = "default_output_cap")]
    pub output_cap_bytes: usize,
    /// Teto de execuções de `exec`/file ops por janela de 60s (circuit breaker).
    #[serde(default = "default_max_exec_per_minute")]
    pub max_exec_per_minute: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connect_timeout_secs: default_connect_timeout(),
            command_timeout_secs: default_command_timeout(),
            output_cap_bytes: default_output_cap(),
            max_exec_per_minute: default_max_exec_per_minute(),
        }
    }
}

impl Limits {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }
    pub fn command_timeout(&self) -> Duration {
        Duration::from_secs(self.command_timeout_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Files {
    /// Substrings que, se presentes no path remoto, bloqueiam a operação de
    /// arquivo (anti-exfiltração de segredo). Case-insensitive.
    #[serde(default = "default_deny_path_patterns")]
    pub deny_path_patterns: Vec<String>,
    /// Substrings que bloqueiam ESCRITA (file_put/file_edit/upload) em paths
    /// de persistência do sistema (T6). Anti-acidente: um agente não deveria
    /// plantar cron/systemd/shell-rc por engano. NÃO se aplica a `exec`.
    #[serde(default = "default_deny_write_patterns")]
    pub deny_write_patterns: Vec<String>,
    /// Cap de bytes para `file_get`.
    #[serde(default = "default_max_get")]
    pub max_get_bytes: usize,
    /// Cap de bytes para conteúdo de `file_put`.
    #[serde(default = "default_max_put")]
    pub max_put_bytes: usize,
}

impl Default for Files {
    fn default() -> Self {
        Files {
            deny_path_patterns: default_deny_path_patterns(),
            deny_write_patterns: default_deny_write_patterns(),
            max_get_bytes: default_max_get(),
            max_put_bytes: default_max_put(),
        }
    }
}

fn default_known_hosts() -> PathBuf {
    PathBuf::from("known_hosts")
}
fn default_connect_timeout() -> u64 {
    10
}
fn default_command_timeout() -> u64 {
    30
}
fn default_output_cap() -> usize {
    1024 * 1024
}
fn default_max_exec_per_minute() -> u32 {
    30
}
fn default_max_get() -> usize {
    1024 * 1024
}
fn default_max_put() -> usize {
    1024 * 1024
}
fn default_deny_path_patterns() -> Vec<String> {
    [
        "shadow",
        "gshadow",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        ".pem",
        ".key",
        ".ppk",
        ".pfx",
        "/etc/ssl/private",
        "authorized_keys",
        ".aws/credentials",
        ".ssh/known_hosts",
        "sudoers",
        "/proc/kcore",
        "/dev/mem",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_deny_write_patterns() -> Vec<String> {
    [
        "/etc/cron",
        "crontab",
        "/etc/systemd",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".ssh/rc",
        "ld.so.preload",
        "pam.d",
        "/etc/passwd",
        "/etc/sudoers",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("lendo config {}: {e}", path.display()))?;
        let mut cfg: Config = toml::from_str(&raw)?;

        // Resolve paths relativos contra o diretório do config.toml.
        let base = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let abs = |p: &PathBuf| -> PathBuf {
            if p.is_absolute() {
                p.clone()
            } else {
                base.join(p)
            }
        };
        cfg.inventory_script = abs(&cfg.inventory_script);
        cfg.resolve_script = abs(&cfg.resolve_script);
        cfg.audit_log = abs(&cfg.audit_log);
        cfg.known_hosts = abs(&cfg.known_hosts);
        // document_path e pwsh_path ficam como vieram (esperados absolutos).
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t6_deny_write_tem_paths_de_persistencia() {
        let pats = default_deny_write_patterns();
        assert!(pats.iter().any(|p| p.contains("cron")));
        assert!(pats.iter().any(|p| p.contains("systemd")));
        assert!(pats.iter().any(|p| p.contains(".bashrc")));
        assert!(pats.iter().any(|p| p.contains("ld.so.preload")));
    }

    #[test]
    fn t6_deny_path_default_tem_segredos() {
        let pats = default_deny_path_patterns();
        assert!(pats.iter().any(|p| p.contains("shadow")));
        assert!(pats.iter().any(|p| p.contains("id_rsa")));
    }
}
