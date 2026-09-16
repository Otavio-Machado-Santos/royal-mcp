//! Tipo `Secret` — a fronteira de credencial forçada por construção.
//!
//! Envolve `secrecy::SecretString` (que faz `zeroize` no drop, limpando a
//! memória). NÃO deriva `Serialize`/`Display`; `Debug` imprime apenas `***`.
//! O valor em claro só é acessível por `expose()`, usado exclusivamente pelo
//! motor de conexão SSH dentro do processo do MCP.
use secrecy::{ExposeSecret, SecretString};

pub struct Secret(SecretString);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(SecretString::from(value))
    }

    /// Único ponto de exposição do valor em claro.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}
