//! Ponte para o Royal: executa o script pwsh de inventário e parseia o JSON.
//! O `pwsh` é subprocesso filho do MCP, nunca exposto ao agente.
use crate::config::Config;
use crate::model::HostRaw;
use anyhow::Context;
use std::process::Command;

pub fn load_hosts(cfg: &Config) -> anyhow::Result<Vec<HostRaw>> {
    let output = Command::new(&cfg.pwsh_path)
        .arg("-NoProfile")
        .arg("-File")
        .arg(&cfg.inventory_script)
        .arg("-DocPath")
        .arg(&cfg.document_path)
        .output()
        .with_context(|| format!("executando pwsh em {}", cfg.pwsh_path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "script de inventário falhou ({}): {}",
            output.status,
            stderr.trim()
        );
    }

    let hosts: Vec<HostRaw> =
        serde_json::from_slice(&output.stdout).context("parseando JSON do inventário")?;
    Ok(hosts)
}
