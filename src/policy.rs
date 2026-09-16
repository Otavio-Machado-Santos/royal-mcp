//! Política de execução: modelo **default-allow** com denylist mínima de
//! comandos CATASTRÓFICOS (irreversíveis).
//!
//! Filosofia: este MCP existe para dar aos agentes acesso SSH REAL sem expor
//! credencial. A fronteira ADVERSARIAL é o escopo de host (`config [scope]`) +
//! a fronteira de credencial (`vault`/`secret`) + o audit hash-chain. A política
//! aqui é apenas controle ANTI-ACIDENTE: recusa o punhado de comandos que
//! destroem o sistema de forma irreversível (formatar disco, `dd` em block
//! device, wipe da raiz, fork bomb, desligar/reiniciar a máquina). Todo o resto
//! executa.
//!
//! Composição de shell (pipes, `;`, `&&`, redireção, interpretadores como
//! `bash`/`python`) é PERMITIDA: o antigo gate de "inspecionabilidade" só gerava
//! atrito sem agregar segurança real — o agente já tem a conexão, a defesa é o
//! escopo, não a sintaxe do comando.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

/// Binários catastróficos: destroem disco/FS ou derrubam a máquina de forma
/// irreversível. Recusados em qualquer posição de comando (a denylist é o
/// ÚNICO default-deny do modelo).
const CATASTROPHIC: &[&str] = &[
    // disco / filesystem
    "dd",
    "shred",
    "wipefs",
    "fdisk",
    "parted",
    "format",
    "mkswap",
    "blkdiscard",
    "mke2fs", // alvo real dos symlinks mkfs.ext*
    "nvme",   // `nvme format` apaga namespaces inteiros
    // boot / power
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init",
    "telinit",
];

/// Wrappers de prefixo: não são o binário "de verdade"; pulamos até o alvo.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "nohup", "time", "env", "nice", "ionice", "stdbuf", "setsid", "command",
];

/// Opções de `sudo`/wrappers que consomem um VALOR no próximo token.
const VALUE_OPTS: &[&str] = &[
    "-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "-U", "-h", "-R", "-t", "-T", "-D",
];

/// Prefixos de block device: escrever neles (via `>` ou `dd`) é destrutivo.
const BLOCK_DEVICES: &[&str] = &[
    "/dev/sd",
    "/dev/nvme",
    "/dev/vd",
    "/dev/hd",
    "/dev/mmcblk",
    "/dev/xvd",
    "/dev/disk",
];

/// Diretórios top-level cujo wipe recursivo é catastrófico.
const CRITICAL_DIRS: &[&str] = &[
    "/etc", "/usr", "/var", "/bin", "/boot", "/lib", "/lib64", "/sbin", "/home", "/root", "/opt",
    "/srv", "/sys", "/proc", "/dev",
];

pub fn classify(command: &str) -> Decision {
    let cmd = command.trim();
    if cmd.is_empty() {
        return Decision::Deny("comando vazio".into());
    }

    // Padrões catastróficos no comando inteiro (independem de posição).
    if let Some(reason) = catastrophic_pattern(cmd) {
        return Decision::Deny(reason);
    }

    // Cada segmento (separado por `;` `|` `&` e newlines) tem seu binário
    // efetivo checado contra a denylist catastrófica.
    for segment in split_segments(cmd) {
        let tokens: Vec<&str> = segment.split_whitespace().collect();
        let Some(bin_idx) = effective_bin_index(&tokens) else {
            continue;
        };
        let bin = base_name(tokens[bin_idx]).to_lowercase();
        if bin.starts_with("mkfs") {
            return Decision::Deny(format!("comando catastrófico bloqueado: {bin}"));
        }
        if CATASTROPHIC.contains(&bin.as_str()) {
            return Decision::Deny(format!("comando catastrófico bloqueado: {bin}"));
        }
        if bin == "rm"
            && let Some(reason) = dangerous_rm(&tokens[bin_idx..])
        {
            return Decision::Deny(reason);
        }
        if (bin == "systemctl" || bin == "service")
            && let Some(reason) = dangerous_service_ctl(&bin, &tokens[bin_idx..])
        {
            return Decision::Deny(reason);
        }
        if bin == "find"
            && let Some(reason) = dangerous_find_delete(&tokens[bin_idx..])
        {
            return Decision::Deny(reason);
        }
    }

    Decision::Allow
}

/// `systemctl`/`service`: desligar a máquina ou derrubar o sshd são
/// catastróficos (lockout irreversível sem acesso out-of-band). Restart de
/// outros serviços segue livre (default-allow); `restart sshd` passa porque
/// se auto-recupera.
fn dangerous_service_ctl(bin: &str, args: &[&str]) -> Option<String> {
    // Pula o próprio binário e opções (-x) até o verbo/alvo.
    let positional: Vec<&str> = args[1..]
        .iter()
        .filter(|t| !t.starts_with('-'))
        .copied()
        .collect();
    let (verb, targets): (&str, &[&str]) = match bin {
        // systemctl <verb> <alvos...>
        "systemctl" => {
            let (v, rest) = positional.split_first()?;
            (*v, rest)
        }
        // service <alvo> <verb>
        _ => {
            let (target, rest) = positional.split_first()?;
            let verb = rest.first().copied().unwrap_or("");
            (verb, std::slice::from_ref(target))
        }
    };
    if matches!(verb, "poweroff" | "reboot" | "halt") {
        return Some(format!("desligar/reiniciar via {bin} bloqueado: {verb}"));
    }
    if matches!(verb, "stop" | "disable" | "mask") {
        for t in targets {
            let svc = base_name(t).trim_end_matches(".service").to_lowercase();
            if svc == "sshd" || svc == "ssh" {
                return Some(format!(
                    "derrubar o SSH bloqueado (lockout): {bin} {verb} {t}"
                ));
            }
        }
    }
    None
}

/// `find <alvo> ... -delete` em alvo crítico é o equivalente funcional de
/// `rm -rf /` — negado. `-delete` em paths não-críticos segue livre.
fn dangerous_find_delete(args: &[&str]) -> Option<String> {
    if !args.contains(&"-delete") {
        return None;
    }
    // Alvos do find são os tokens posicionais antes da primeira opção.
    for t in &args[1..] {
        if t.starts_with('-') {
            break;
        }
        if is_root_ish(t) {
            return Some(format!("find -delete em alvo crítico bloqueado: {t}"));
        }
    }
    None
}

/// True se algum segmento inicia com `sudo`/`doas` em posição de comando.
/// Usado pelo motor SSH para decidir se injeta a senha via stdin (`sudo -S`).
pub fn command_uses_sudo(command: &str) -> bool {
    split_segments(command).iter().any(|seg| {
        seg.split_whitespace()
            .next()
            .map(|t| matches!(base_name(t).to_lowercase().as_str(), "sudo" | "doas"))
            .unwrap_or(false)
    })
}

/// Reescreve o `sudo`/`doas` líder de cada segmento (separado por `;`/`&&`/`||`/
/// newline) para `sudo -S -p '' …`, preservando os separadores e pipes internos.
/// Assim o `sudo` lê a senha do stdin (que o motor SSH injeta) sem exigir TTY.
/// `sudo` no MEIO de um pipe (ex.: `foo | sudo tee x`) NÃO é reescrito — o stdin
/// naquele caso é o pipe, não a senha (limitação conhecida).
pub fn rewrite_sudo(command: &str) -> String {
    let mut result = String::with_capacity(command.len() + 24);
    let mut piece = String::new();
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if (c == '&' || c == '|') && i + 1 < chars.len() && chars[i + 1] == c {
            result.push_str(&inject_leading_sudo(&piece));
            piece.clear();
            result.push(c);
            result.push(c);
            i += 2;
            continue;
        }
        if c == ';' || c == '\n' || c == '\r' {
            result.push_str(&inject_leading_sudo(&piece));
            piece.clear();
            result.push(c);
            i += 1;
            continue;
        }
        piece.push(c);
        i += 1;
    }
    result.push_str(&inject_leading_sudo(&piece));
    result
}

/// Insere `-S -p ''` logo após o `sudo`/`doas` líder de UM pedaço, se ele já não
/// pedir modo não-interativo. Preserva indentação e o resto do pedaço.
fn inject_leading_sudo(piece: &str) -> String {
    let leading_ws: String = piece.chars().take_while(|c| c.is_whitespace()).collect();
    let rest = &piece[leading_ws.len()..];
    let Some(first) = rest.split_whitespace().next() else {
        return piece.to_string();
    };
    if !matches!(base_name(first).to_lowercase().as_str(), "sudo" | "doas") {
        return piece.to_string();
    }
    // Já é não-interativo? Não mexe.
    let already = rest
        .split_whitespace()
        .skip(1)
        .take_while(|t| t.starts_with('-'))
        .any(|t| matches!(t, "-S" | "-n" | "-A" | "--non-interactive" | "--stdin"));
    if already {
        return piece.to_string();
    }
    let after_first = rest[first.len()..].trim_start();
    if after_first.is_empty() {
        format!("{leading_ws}{first} -S -p ''")
    } else {
        format!("{leading_ws}{first} -S -p '' {after_first}")
    }
}

/// Decide a forma final do comando e se a senha do vault deve ser injetada no
/// stdin do canal. Retorna (comando_final, injeta_senha).
///
/// REGRA DE SEGURANÇA (C1): a senha SÓ é injetada quando o comando FINAL
/// contém `sudo -S` — seja porque nós reescrevemos, seja porque o chamador
/// escreveu explicitamente. Sem essa checagem, comandos como `sudo -n true; cat`
/// ou `cat | sudo tee x` (que `command_uses_sudo` aprova mas `rewrite_sudo`
/// não reescreve) receberiam a senha no stdin sem nenhum `sudo -S` para
/// consumi-la — e outro processo do pipeline (`cat`) leria o stdin e devolveria
/// a senha no stdout da tool, cruzando a fronteira de credencial.
pub fn prepare_sudo_exec(command: &str, has_password: bool) -> (String, bool) {
    if !has_password || !command_uses_sudo(command) {
        return (command.to_string(), false);
    }
    let rewritten = rewrite_sudo(command);
    let feed = rewritten.contains("sudo -S");
    (rewritten, feed)
}

/// Quebra o comando em segmentos por `;` `|` `&` e newlines (sem tratar aspas —
/// isto é anti-acidente, não anti-adversarial). `&&`/`||` viram separadores;
/// segmentos vazios são descartados.
fn split_segments(cmd: &str) -> Vec<String> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    for ch in cmd.chars() {
        match ch {
            ';' | '|' | '&' | '\n' | '\r' => {
                if !cur.trim().is_empty() {
                    segs.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        segs.push(cur.trim().to_string());
    }
    segs
}

/// Índice do binário efetivo num segmento tokenizado, pulando wrappers de
/// prefixo (`sudo`/`env`/`nohup`/…), suas flags e atribuições `VAR=val`.
fn effective_bin_index(tokens: &[&str]) -> Option<usize> {
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        // Atribuição de env no início (VAR=val) — pula.
        if !tok.starts_with('-') && tok.contains('=') {
            i += 1;
            continue;
        }
        if WRAPPERS.contains(&base_name(tok).to_lowercase().as_str()) {
            i += 1;
            while i < tokens.len() {
                let t = tokens[i];
                if t.starts_with('-') {
                    let takes_value = VALUE_OPTS.contains(&t);
                    i += 1;
                    if takes_value && i < tokens.len() && !tokens[i].starts_with('-') {
                        i += 1; // pula o valor da opção (ex.: `-u root`)
                    }
                    continue;
                }
                if t.contains('=') {
                    i += 1; // atribuição VAR=val entre wrapper e binário
                    continue;
                }
                break;
            }
            continue;
        }
        return Some(i);
    }
    None
}

/// Detecta `rm` catastrófico: `--no-preserve-root`, ou recursivo+force em alvo
/// raiz / diretório crítico. `rm` comum (arquivos, dirs de trabalho) passa.
fn dangerous_rm(tokens: &[&str]) -> Option<String> {
    let mut recursive = false;
    let mut force = false;
    let mut targets: Vec<&str> = Vec::new();
    for &t in &tokens[1..] {
        match t {
            "--no-preserve-root" => {
                return Some("rm --no-preserve-root bloqueado (wipe de raiz)".into());
            }
            "--recursive" => recursive = true,
            "--force" => force = true,
            _ if t.starts_with("--") => {}
            _ if t.starts_with('-') && t.len() > 1 => {
                for ch in t[1..].chars() {
                    match ch {
                        'r' | 'R' => recursive = true,
                        'f' => force = true,
                        _ => {}
                    }
                }
            }
            _ => targets.push(t),
        }
    }
    if recursive && force {
        for tgt in &targets {
            if is_root_ish(tgt) {
                return Some(format!(
                    "rm recursivo/force em alvo crítico bloqueado: {tgt}"
                ));
            }
        }
    }
    None
}

/// True se o alvo é a raiz, `~`, `*`, ou um diretório top-level crítico
/// (com ou sem `/`/`*` no fim).
fn is_root_ish(target: &str) -> bool {
    let t = target.trim();
    if t == "~" || t == "~/" {
        return true;
    }
    let norm = t.trim_end_matches('*').trim_end_matches('/');
    if norm.is_empty() {
        // "/", "/*", "*" → wipe total
        return true;
    }
    CRITICAL_DIRS.contains(&norm)
}

/// Padrões catastróficos que independem de posição: fork bomb e escrita em
/// block device via redireção.
fn catastrophic_pattern(cmd: &str) -> Option<String> {
    let lower = cmd.to_lowercase();
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains(":(){") {
        return Some("fork bomb bloqueada".into());
    }
    if compact.contains(">/proc/sysrq-trigger") {
        return Some("escrita em sysrq-trigger bloqueada (crash do kernel)".into());
    }
    redirect_to_block_device(&lower)
}

/// Detecta `> /dev/sdX` (e afins): redireção de escrita para um block device.
/// Só dispara quando o device aparece LOGO APÓS um `>` (leitura de device p/
/// arquivo, ex.: `cat /dev/sda > /tmp/x`, não é bloqueada aqui).
fn redirect_to_block_device(lower: &str) -> Option<String> {
    let mut search_from = 0;
    while let Some(pos) = lower[search_from..].find('>') {
        let start = search_from + pos + 1;
        let rest = lower[start..].trim_start_matches('>').trim_start();
        for dev in BLOCK_DEVICES {
            if rest.starts_with(dev) {
                return Some(format!("escrita em block device bloqueada: {dev}"));
            }
        }
        search_from = start;
    }
    None
}

/// Tira diretório, aspas envolventes e sufixo `.exe` do token.
/// Aspas importam: `"dd" if=...` não pode escapar da denylist (T5).
fn base_name(tok: &str) -> String {
    let unquoted = tok.trim_matches(['"', '\'']);
    let t = unquoted.rsplit(['/', '\\']).next().unwrap_or(unquoted);
    t.strip_suffix(".exe").unwrap_or(t).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leitura_e_composicao_executam() {
        assert_eq!(classify("uptime"), Decision::Allow);
        assert_eq!(classify("df -h"), Decision::Allow);
        assert_eq!(classify("/usr/bin/hostname"), Decision::Allow);
        assert_eq!(classify("ps aux | grep -i ssh"), Decision::Allow);
        assert_eq!(
            classify("journalctl -u nginx | tail -n 50"),
            Decision::Allow
        );
        assert_eq!(classify("uptime; free -m && df -h"), Decision::Allow);
        assert_eq!(classify("cat /etc/hosts > /tmp/out"), Decision::Allow);
        assert_eq!(classify("echo $(hostname)"), Decision::Allow);
        assert_eq!(classify("bash -c 'ls -la /var/log'"), Decision::Allow);
        assert_eq!(classify("python3 -c 'print(1)'"), Decision::Allow);
    }

    #[test]
    fn sudo_e_mutacoes_comuns_executam() {
        assert_eq!(classify("sudo systemctl restart nginx"), Decision::Allow);
        assert_eq!(
            classify("sudo -u root systemctl status nginx"),
            Decision::Allow
        );
        assert_eq!(classify("sudo mv /tmp/x /etc/fbx/x"), Decision::Allow);
        assert_eq!(classify("sudo chown root:root /etc/fbx/x"), Decision::Allow);
        assert_eq!(classify("sudo chmod 644 /etc/fbx/x"), Decision::Allow);
        assert_eq!(classify("apt install -y htop"), Decision::Allow);
        assert_eq!(classify("mysql -e 'show databases'"), Decision::Allow);
        assert_eq!(classify("kill -9 12345"), Decision::Allow);
        assert_eq!(classify("rm /tmp/malware"), Decision::Allow);
        assert_eq!(classify("rm -rf /tmp/xmrig"), Decision::Allow);
        assert_eq!(classify("rm -rf ./node_modules"), Decision::Allow);
    }

    #[test]
    fn catastrofico_recusa() {
        assert!(matches!(classify("mkfs.ext4 /dev/sdb"), Decision::Deny(_)));
        assert!(matches!(
            classify("dd if=/dev/zero of=/dev/sda"),
            Decision::Deny(_)
        ));
        assert!(matches!(classify("shred -u /dev/sda"), Decision::Deny(_)));
        assert!(matches!(classify("reboot"), Decision::Deny(_)));
        assert!(matches!(classify("sudo reboot"), Decision::Deny(_)));
        assert!(matches!(classify("shutdown -h now"), Decision::Deny(_)));
        assert!(matches!(classify(":(){ :|:& };:"), Decision::Deny(_)));
        assert!(matches!(classify("cat x > /dev/sda"), Decision::Deny(_)));
        assert!(matches!(
            classify("echo 1 >/dev/nvme0n1"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn rm_raiz_recusa_mas_local_permite() {
        assert!(matches!(classify("rm -rf /"), Decision::Deny(_)));
        assert!(matches!(classify("rm -rf /*"), Decision::Deny(_)));
        assert!(matches!(classify("sudo rm -rf /etc"), Decision::Deny(_)));
        assert!(matches!(
            classify("rm -rf --no-preserve-root /"),
            Decision::Deny(_)
        ));
        assert!(matches!(classify("uptime; rm -rf /"), Decision::Deny(_)));
        assert_eq!(classify("rm -rf /tmp/build"), Decision::Allow);
    }

    #[test]
    fn vazio_recusa() {
        assert!(matches!(classify("   "), Decision::Deny(_)));
    }

    #[test]
    fn detecta_sudo() {
        assert!(command_uses_sudo("sudo systemctl restart nginx"));
        assert!(command_uses_sudo("uptime; sudo mv a b"));
        assert!(!command_uses_sudo("systemctl status nginx"));
        assert!(!command_uses_sudo("echo sudo"));
    }

    #[test]
    fn reescreve_sudo_lider() {
        assert_eq!(
            rewrite_sudo("sudo mv /tmp/x /etc/fbx/x"),
            "sudo -S -p '' mv /tmp/x /etc/fbx/x"
        );
        assert_eq!(
            rewrite_sudo("sudo systemctl restart nginx && sudo systemctl status nginx"),
            "sudo -S -p '' systemctl restart nginx && sudo -S -p '' systemctl status nginx"
        );
        // Já não-interativo: não mexe.
        assert_eq!(rewrite_sudo("sudo -n id"), "sudo -n id");
        // Sem sudo: inalterado.
        assert_eq!(rewrite_sudo("ps aux | grep x"), "ps aux | grep x");
        // sudo no meio de pipe não é reescrito.
        assert_eq!(rewrite_sudo("cat f | sudo tee x"), "cat f | sudo tee x");
    }

    #[test]
    fn c1_senha_nunca_injetada_sem_sudo_s_no_comando_final() {
        // Caso normal: reescrito → injeta.
        let (cmd, feed) = prepare_sudo_exec("sudo id", true);
        assert!(feed);
        assert!(cmd.contains("sudo -S"));

        // C1-a: `sudo -n` NÃO é reescrito; o `cat` seguinte leria o stdin e
        // devolveria a senha no stdout da tool. Sem -S no final → NÃO injeta.
        let (cmd, feed) = prepare_sudo_exec("sudo -n true; cat", true);
        assert!(!feed, "senha vazaria pelo cat: {cmd}");

        // C1-b: sudo no meio de pipe não é reescrito; a senha ficaria no pipe
        // para outro processo. Sem -S no final → NÃO injeta.
        let (cmd, feed) = prepare_sudo_exec("cat /var/log/x | sudo tee /tmp/y", true);
        assert!(!feed, "senha ficaria no pipe: {cmd}");

        // `sudo -A` (askpass) idem: não é reescrito, não injeta.
        let (_, feed) = prepare_sudo_exec("sudo -A id; cat", true);
        assert!(!feed);

        // sudo -S explícito do chamador: consome a senha corretamente → injeta.
        let (cmd, feed) = prepare_sudo_exec("sudo -S cat /etc/fbx/conf", true);
        assert!(feed);
        assert_eq!(cmd, "sudo -S cat /etc/fbx/conf");

        // Sem senha disponível (host por chave): nunca injeta.
        let (_, feed) = prepare_sudo_exec("sudo id", false);
        assert!(!feed);

        // Sem sudo: comando inalterado, não injeta.
        let (cmd, feed) = prepare_sudo_exec("uptime", true);
        assert!(!feed);
        assert_eq!(cmd, "uptime");

        // Misto: um sudo -n falha seco, mas o segundo sudo é reescrito e
        // consome a senha → injeta (caso legítimo).
        let (cmd, feed) = prepare_sudo_exec("sudo -n true; sudo systemctl restart zabbix", true);
        assert!(feed);
        assert!(cmd.contains("sudo -S -p '' systemctl restart zabbix"));
    }

    // ---- T5: hardening anti-catástrofe ----

    #[test]
    fn t5_aspas_no_binario_sao_normalizadas() {
        assert!(matches!(
            classify(r#""dd" if=/dev/zero of=/dev/sda"#),
            Decision::Deny(_)
        ));
        assert!(matches!(classify("'rm' -rf /"), Decision::Deny(_)));
        assert!(matches!(
            classify(r#""shutdown" -h now"#),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn t5_formatadores_alternativos_negados() {
        assert!(matches!(classify("mke2fs /dev/sda1"), Decision::Deny(_)));
        assert!(matches!(
            classify("sudo mke2fs /dev/sda1"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            classify("nvme format /dev/nvme0"),
            Decision::Deny(_)
        ));
        assert!(matches!(classify("telinit 0"), Decision::Deny(_)));
    }

    #[test]
    fn t5_systemctl_verbs_catastroficos_e_sshd_negados() {
        assert!(matches!(classify("systemctl poweroff"), Decision::Deny(_)));
        assert!(matches!(classify("systemctl reboot"), Decision::Deny(_)));
        assert!(matches!(classify("systemctl halt"), Decision::Deny(_)));
        assert!(matches!(
            classify("sudo systemctl poweroff"),
            Decision::Deny(_)
        ));
        // derrubar o sshd = lockout total (sem acesso out-of-band)
        assert!(matches!(classify("systemctl stop sshd"), Decision::Deny(_)));
        assert!(matches!(classify("systemctl stop ssh"), Decision::Deny(_)));
        assert!(matches!(
            classify("systemctl disable sshd"),
            Decision::Deny(_)
        ));
        assert!(matches!(classify("systemctl mask sshd"), Decision::Deny(_)));
        assert!(matches!(classify("service sshd stop"), Decision::Deny(_)));
        // default-allow intacto: restart/status de outros serviços seguem livres
        assert_eq!(classify("systemctl restart nginx"), Decision::Allow);
        assert_eq!(classify("systemctl status sshd"), Decision::Allow);
        assert_eq!(classify("systemctl restart sshd"), Decision::Allow); // auto-recupera
        assert_eq!(classify("service nginx stop"), Decision::Allow);
    }

    #[test]
    fn t5_find_delete_em_alvo_critico_negado() {
        assert!(matches!(classify("find / -delete"), Decision::Deny(_)));
        assert!(matches!(
            classify("find /etc -name '*.bak' -delete"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            classify("sudo find / -xdev -delete"),
            Decision::Deny(_)
        ));
        // não crítico: segue livre
        assert_eq!(classify("find /tmp -delete"), Decision::Allow);
        assert_eq!(classify("find /var/log -name '*.old'"), Decision::Allow);
    }

    #[test]
    fn t5_sysrq_trigger_negado() {
        assert!(matches!(
            classify("echo c > /proc/sysrq-trigger"),
            Decision::Deny(_)
        ));
        // leitura é livre
        assert_eq!(classify("cat /proc/sysrq-trigger"), Decision::Allow);
    }
}
