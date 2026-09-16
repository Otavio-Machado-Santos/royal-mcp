//! Modelo interno (`HostRecord`) e DTO de saída (`HostView`).
//! A separação É a fronteira: `HostView` é o único struct que o agente recebe e
//! não tem campo de credencial — não há como vazar segredo pela serialização.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Linha crua emitida pelo script pwsh de inventário (JSON). Uso interno.
#[derive(Debug, Deserialize)]
pub struct HostRaw {
    pub id: String,
    pub name: String,
    pub uri: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    pub has_password: bool,
    pub has_key: bool,
    /// Caminho da pasta no Royal (ex.: "Clientes/ClientA"). Vazio na raiz.
    #[serde(default)]
    pub folder: String,
}

/// Como o host autentica (sem expor o segredo em si).
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    Password,
    Key,
    None,
}

/// Registro interno do host. NÃO deriva `Serialize`.
#[derive(Debug)]
pub struct HostRecord {
    pub id: String,
    pub name: String,
    pub uri: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthKind,
    pub folder: String,
}

impl From<HostRaw> for HostRecord {
    fn from(r: HostRaw) -> Self {
        let auth = if r.has_key {
            AuthKind::Key
        } else if r.has_password {
            AuthKind::Password
        } else {
            AuthKind::None
        };
        HostRecord {
            id: r.id,
            name: r.name,
            uri: r.uri,
            port: r.port,
            username: r.username,
            auth,
            folder: r.folder,
        }
    }
}

/// DTO de saída — ÚNICO struct que o agente recebe. Sem credencial.
#[derive(Debug, Serialize, JsonSchema)]
pub struct HostView {
    pub id: String,
    pub name: String,
    pub uri: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthKind,
    pub folder: String,
}

impl HostView {
    pub fn of(h: &HostRecord) -> Self {
        HostView {
            id: h.id.clone(),
            name: h.name.clone(),
            uri: h.uri.clone(),
            port: h.port,
            username: h.username.clone(),
            auth: h.auth,
            folder: h.folder.clone(),
        }
    }
}
