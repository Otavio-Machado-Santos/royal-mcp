//! Inventário em memória + interseção de escopo.
//! O agente só enxerga a interseção com a allowlist: um host é visível se seu
//! NOME está em `scope.allow_host_names` OU sua PASTA casa com `scope.allow_folders`.
//! Sentinela: `ALL_HOSTS` (ou `*`) em qualquer um dos dois campos libera TODOS
//! os hosts do documento — escape hatch explícito ao default-deny.
use crate::config::Config;
use crate::model::{HostRecord, HostView};
use crate::royal;
use std::collections::HashSet;

/// Valores que, em allow_host_names OU allow_folders, liberam todo o inventário.
const ALLOW_ALL_SENTINELS: [&str; 2] = ["all_hosts", "*"];

fn is_allow_all(value: &str) -> bool {
    ALLOW_ALL_SENTINELS.contains(&value.trim().to_lowercase().as_str())
}

pub struct Inventory {
    all: Vec<HostRecord>,
    allow_names: HashSet<String>,
    allow_folders: Vec<String>,
    /// Sentinela `ALL_HOSTS`/`*` presente: todo host fica visível.
    allow_all: bool,
}

impl Inventory {
    pub fn load(cfg: &Config) -> anyhow::Result<Self> {
        let all: Vec<HostRecord> = royal::load_hosts(cfg)?
            .into_iter()
            .map(Into::into)
            .collect();
        // Sentinela ALL_HOSTS/* em qualquer um dos campos libera todo o inventário.
        let allow_all = cfg.scope.allow_host_names.iter().any(|v| is_allow_all(v))
            || cfg.scope.allow_folders.iter().any(|v| is_allow_all(v));
        let allow_names = cfg.scope.allow_host_names.iter().cloned().collect();
        // Filtra entradas vazias: `"qualquer".contains("")` é sempre true, então
        // uma string vazia em allow_folders abriria o escopo para TODOS os hosts.
        let allow_folders = cfg
            .scope
            .allow_folders
            .iter()
            .map(|f| f.trim().to_lowercase())
            .filter(|f| !f.is_empty())
            .collect();
        if allow_all {
            tracing::warn!(
                total = all.len(),
                "scope.allow_all ativo (ALL_HOSTS): TODOS os hosts do documento estão visíveis ao agente"
            );
        }
        let inv = Inventory {
            all,
            allow_names,
            allow_folders,
            allow_all,
        };
        if inv.total() > 0 && inv.visible_count() == 0 {
            tracing::warn!(
                total = inv.total(),
                "escopo vazio: nenhum host visível — verifique scope.allow_host_names / allow_folders"
            );
        }
        Ok(inv)
    }

    /// Total bruto no documento (inclui fora do escopo). Para diagnóstico/log.
    pub fn total(&self) -> usize {
        self.all.len()
    }

    fn in_scope(&self, h: &HostRecord) -> bool {
        if self.allow_all {
            return true;
        }
        if self.allow_names.contains(&h.name) {
            return true;
        }
        if self.allow_folders.is_empty() {
            return false;
        }
        let folder = h.folder.to_lowercase();
        self.allow_folders.iter().any(|f| folder.contains(f))
    }

    /// Hosts visíveis ao agente = interseção com a allowlist (nome OU pasta).
    fn visible(&self) -> impl Iterator<Item = &HostRecord> {
        self.all.iter().filter(move |h| self.in_scope(h))
    }

    pub fn query(&self, name_filter: Option<&str>, folder_filter: Option<&str>) -> Vec<HostView> {
        self.visible()
            .filter(|h| match name_filter {
                Some(pat) if !pat.is_empty() => glob_match(pat, &h.name),
                _ => true,
            })
            .filter(|h| match folder_filter {
                Some(pat) if !pat.is_empty() => {
                    h.folder.to_lowercase().contains(&pat.to_lowercase())
                }
                _ => true,
            })
            .map(HostView::of)
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<HostView> {
        self.visible().find(|h| h.id == id).map(HostView::of)
    }

    /// Apenas nomes de usuário (credencial) distintos dos hosts visíveis.
    pub fn credentials(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .visible()
            .map(|h| h.username.clone())
            .filter(|u| !u.is_empty())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Quantidade de hosts visíveis (para diagnóstico/refresh).
    pub fn visible_count(&self) -> usize {
        self.visible().count()
    }

    /// Resolve um host informado pelo agente para operação (T4). A ordem é
    /// estrita: ID exato → nome exato (case-insensitive) → substring. Substring
    /// com mais de um candidato é AMBÍGUA — o chamador deve negar e listar os
    /// candidatos em vez de executar no host errado.
    pub fn resolve(&self, name_or_id: &str) -> HostResolution {
        // 1) ID exato.
        if let Some(h) = self.visible().find(|h| h.id == name_or_id) {
            return HostResolution::Found(HostView::of(h));
        }
        // 2) Nome exato (case-insensitive) — sempre vence substring.
        if let Some(h) = self
            .visible()
            .find(|h| h.name.eq_ignore_ascii_case(name_or_id))
        {
            return HostResolution::Found(HostView::of(h));
        }
        // 3) Substring (case-insensitive).
        let needle = name_or_id.to_lowercase();
        let matches: Vec<&HostRecord> = self
            .visible()
            .filter(|h| h.name.to_lowercase().contains(&needle))
            .collect();
        match matches.len() {
            0 => HostResolution::NotFound,
            1 => HostResolution::Found(HostView::of(matches[0])),
            _ => HostResolution::Ambiguous(matches.iter().map(|h| h.name.clone()).collect()),
        }
    }
}

/// Resultado da resolução de um host para operação (T4).
pub enum HostResolution {
    Found(HostView),
    /// Substring casou com 2+ hosts — negar e listar candidatos.
    Ambiguous(Vec<String>),
    NotFound,
}

/// Glob case-insensitive simples: sem `*` = substring; com `*` = fragmentos em ordem.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.to_lowercase();
    let t = text.to_lowercase();
    if !p.contains('*') {
        return t.contains(&p);
    }
    let mut pos = 0;
    for part in p.split('*') {
        if part.is_empty() {
            continue;
        }
        match t[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthKind, HostRecord};

    fn host(name: &str, folder: &str) -> HostRecord {
        HostRecord {
            id: name.to_string(),
            name: name.to_string(),
            uri: "1.2.3.4".to_string(),
            port: 22,
            username: "root".to_string(),
            auth: AuthKind::Password,
            folder: folder.to_string(),
        }
    }

    fn inv(names: &[&str], folders: &[&str], hosts: Vec<HostRecord>) -> Inventory {
        let allow_all =
            names.iter().any(|v| is_allow_all(v)) || folders.iter().any(|v| is_allow_all(v));
        Inventory {
            all: hosts,
            allow_names: names.iter().map(|s| s.to_string()).collect(),
            allow_folders: folders
                .iter()
                .map(|f| f.trim().to_lowercase())
                .filter(|f| !f.is_empty())
                .collect(),
            allow_all,
        }
    }

    #[test]
    fn sentinel_all_hosts_libera_tudo() {
        let hosts = vec![host("A", "Cli1"), host("B", "Cli2"), host("C", "Cli3")];
        let i = inv(&["ALL_HOSTS"], &[], hosts);
        assert_eq!(i.visible_count(), 3);
    }

    #[test]
    fn sentinel_funciona_em_allow_folders_e_e_case_insensitive() {
        let hosts = vec![host("A", "Cli1"), host("B", "Cli2")];
        let i = inv(&[], &["all_hosts"], hosts);
        assert_eq!(i.visible_count(), 2);
    }

    #[test]
    fn asterisco_tambem_libera_tudo() {
        let hosts = vec![host("A", "Cli1"), host("B", "Cli2")];
        let i = inv(&[], &["*"], hosts);
        assert_eq!(i.visible_count(), 2);
    }

    #[test]
    fn sem_sentinel_mantem_default_deny() {
        let hosts = vec![host("A", "Cli1"), host("B", "Cli2"), host("C", "Cli3")];
        let i = inv(&["A"], &["cli2"], hosts);
        // Visíveis: "A" por nome + "B" por pasta Cli2. "C" fica fora.
        assert_eq!(i.visible_count(), 2);
    }

    #[test]
    fn escopo_vazio_nao_libera_nada() {
        let hosts = vec![host("A", "Cli1"), host("B", "Cli2")];
        let i = inv(&[], &[], hosts);
        assert_eq!(i.visible_count(), 0);
    }

    // ---- T4: resolução exata para operação ----

    fn inv_all(names: Vec<&str>) -> Inventory {
        // IDs distintos dos nomes para exercitar a ordem ID→nome→substring.
        let hosts = names
            .into_iter()
            .enumerate()
            .map(|(i, n)| HostRecord {
                id: format!("guid-{i}"),
                name: n.to_string(),
                uri: "1.2.3.4".to_string(),
                port: 22,
                username: "root".to_string(),
                auth: AuthKind::Password,
                folder: "F".to_string(),
            })
            .collect();
        inv(&["ALL_HOSTS"], &[], hosts)
    }

    #[test]
    fn t4_id_exato_vence() {
        let i = inv_all(vec!["web-01", "web-02"]);
        match i.resolve("guid-1") {
            HostResolution::Found(h) => assert_eq!(h.name, "web-02"),
            _ => panic!("esperava Found por ID"),
        }
    }

    #[test]
    fn t4_nome_exato_vence_substring() {
        // "web" é nome exato de um host E substring de outros dois.
        let i = inv_all(vec!["web-01", "web", "web-02"]);
        match i.resolve("web") {
            HostResolution::Found(h) => assert_eq!(h.name, "web"),
            HostResolution::Ambiguous(c) => panic!("nome exato não pode ser ambíguo: {c:?}"),
            HostResolution::NotFound => panic!("esperava Found"),
        }
    }

    #[test]
    fn t4_nome_exato_case_insensitive() {
        let i = inv_all(vec!["ACME - PROD"]);
        match i.resolve("acme - prod") {
            HostResolution::Found(h) => assert_eq!(h.name, "ACME - PROD"),
            _ => panic!("esperava Found case-insensitive"),
        }
    }

    #[test]
    fn t4_substring_ambigua_lista_candidatos() {
        let i = inv_all(vec!["web-01", "web-02", "db-01"]);
        match i.resolve("web-") {
            HostResolution::Ambiguous(c) => assert_eq!(c, vec!["web-01", "web-02"]),
            _ => panic!("esperava Ambiguous"),
        }
    }

    #[test]
    fn t4_substring_unica_resolve() {
        let i = inv_all(vec!["web-01", "db-01"]);
        match i.resolve("web-") {
            HostResolution::Found(h) => assert_eq!(h.name, "web-01"),
            _ => panic!("esperava Found"),
        }
    }

    #[test]
    fn t4_nao_encontrado() {
        let i = inv_all(vec!["web-01"]);
        assert!(matches!(i.resolve("zzz"), HostResolution::NotFound));
    }
}
