//! Audit log append-only com hash-chain. Cada linha carrega o hash da anterior;
//! adulterar uma linha quebra a cadeia. Args já chegam mascarados do chamador.
//!
//! Endurecimento (T6):
//! - arquivo criado com permissão **0600** (pode conter comandos em claro);
//! - a cadeia SÓ avança quando o append no arquivo é bem-sucedido — uma falha
//!   de disco não quebra a verificação silenciosamente; a entrada seguinte
//!   carrega `append_failed: true`;
//! - a primeira linha de uma cadeia nova (arquivo ausente/vazio) marca
//!   `chain_restart: true` — um rastro apagado não parece válido;
//! - a recuperação do último hash no startup lê apenas o FIM do arquivo
//!   (seek reverso), não o arquivo inteiro.
use anyhow::Context;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Quantidade de bytes lidos do fim do arquivo para achar a última linha.
const TAIL_READ: u64 = 16 * 1024;

struct ChainState {
    last_hash: String,
    /// Primeira escrita após abrir sem arquivo prévio: marca chain_restart.
    fresh_chain: bool,
    /// Falha de append na entrada anterior: registra na próxima.
    append_failed: bool,
}

pub struct AuditLog {
    path: PathBuf,
    state: Mutex<ChainState>,
}

impl AuditLog {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        // Recupera o hash da última linha para continuar a cadeia entre
        // execuções — lendo só o fim do arquivo (T6), não tudo.
        let (last_hash, fresh) = match read_last_hash(&path) {
            Some(h) => (h, false),
            None => ("GENESIS".to_string(), true),
        };
        Ok(AuditLog {
            path,
            state: Mutex::new(ChainState {
                last_hash,
                fresh_chain: fresh,
                append_failed: false,
            }),
        })
    }

    pub fn record(&self, tool: &str, args: serde_json::Value, result: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let prev = guard.last_hash.clone();

        let mut entry = json!({
            "ts": ts, "tool": tool, "args": args, "result": result, "prev": prev,
        });
        if guard.fresh_chain {
            entry["chain_restart"] = json!(true);
        }
        if guard.append_failed {
            entry["append_failed"] = json!(true);
        }

        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(entry.to_string().as_bytes());
        let hash: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        entry["hash"] = json!(hash);

        match self.append_line(&entry) {
            Ok(()) => {
                // A cadeia SÓ avança com a linha persistida (T6).
                guard.last_hash = hash;
                guard.fresh_chain = false;
                guard.append_failed = false;
            }
            Err(e) => {
                tracing::error!(error = %e, "falha ao gravar audit log — cadeia NÃO avança");
                guard.append_failed = true;
            }
        }
    }

    fn append_line(&self, entry: &serde_json::Value) -> anyhow::Result<()> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        // T6: o audit pode conter comandos em claro — só o dono lê.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&self.path)
            .with_context(|| format!("abrindo audit log {}", self.path.display()))?;
        writeln!(f, "{entry}")?;
        Ok(())
    }
}

/// Lê apenas os últimos bytes do arquivo e extrai o hash da última linha.
fn read_last_hash(path: &PathBuf) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let start = len.saturating_sub(TAIL_READ);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).ok()?;
    let line = buf.lines().last()?;
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    v.get("hash")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("audit-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn t6_arquivo_criado_com_permissao_0600() {
        let p = temp_log("perms");
        let log = AuditLog::open(p.clone()).unwrap();
        log.record("exec", json!({"a": 1}), "ok");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode={mode:o}");
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn t6_primeira_linha_marca_chain_restart() {
        let p = temp_log("restart");
        let log = AuditLog::open(p.clone()).unwrap();
        log.record("exec", json!({}), "ok");
        let content = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(v["chain_restart"], json!(true));
        assert_eq!(v["prev"], json!("GENESIS"));
        // Segunda linha NÃO marca.
        log.record("exec", json!({}), "ok2");
        let content = std::fs::read_to_string(&p).unwrap();
        let v2: serde_json::Value = serde_json::from_str(content.lines().nth(1).unwrap()).unwrap();
        assert!(v2.get("chain_restart").is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn t6_cadeia_encadeia_e_reabre_sem_ler_tudo() {
        let p = temp_log("chain");
        let log = AuditLog::open(p.clone()).unwrap();
        log.record("a", json!({}), "r1");
        log.record("b", json!({}), "r2");
        drop(log);
        let content = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let h1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let h2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(h2["prev"], h1["hash"]);
        // Reabertura: continua a cadeia a partir da última linha.
        let log2 = AuditLog::open(p.clone()).unwrap();
        log2.record("c", json!({}), "r3");
        let content = std::fs::read_to_string(&p).unwrap();
        let h3: serde_json::Value = serde_json::from_str(content.lines().nth(2).unwrap()).unwrap();
        assert_eq!(h3["prev"], h2["hash"]);
        assert!(h3.get("chain_restart").is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn t6_recupera_hash_com_arquivo_grande() {
        // > TAIL_READ: a recuperação deve funcionar lendo só o fim.
        let p = temp_log("big");
        let log = AuditLog::open(p.clone()).unwrap();
        for i in 0..200 {
            log.record("x", json!({"i": i, "pad": "y".repeat(200)}), "ok");
        }
        drop(log);
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.len() as u64 > TAIL_READ);
        let last: serde_json::Value =
            serde_json::from_str(content.lines().last().unwrap()).unwrap();
        let log2 = AuditLog::open(p.clone()).unwrap();
        log2.record("z", json!({}), "fim");
        let content = std::fs::read_to_string(&p).unwrap();
        let new_last: serde_json::Value =
            serde_json::from_str(content.lines().last().unwrap()).unwrap();
        assert_eq!(new_last["prev"], last["hash"]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn t6_append_falho_nao_avanca_cadeia_e_marca_proxima() {
        let p = temp_log("fail");
        let log = AuditLog::open(p.clone()).unwrap();
        log.record("a", json!({}), "r1");
        let content = std::fs::read_to_string(&p).unwrap();
        let h1: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        // Transforma o arquivo em diretório: todo append falha.
        drop(log);
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        let log2 = AuditLog {
            path: p.clone(),
            state: Mutex::new(ChainState {
                last_hash: h1["hash"].as_str().unwrap().to_string(),
                fresh_chain: false,
                append_failed: false,
            }),
        };
        log2.record("b", json!({}), "vai-falhar");
        // Hash NÃO avançou: a próxima tentativa usa o mesmo prev.
        {
            let guard = log2.state.lock().unwrap();
            assert_eq!(guard.last_hash, h1["hash"].as_str().unwrap());
            assert!(guard.append_failed);
        }
        std::fs::remove_dir(&p).unwrap();
    }
}
