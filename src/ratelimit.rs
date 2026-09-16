//! Rate-limit simples (janela FIXA / tumbling de 60s) usado como circuit breaker
//! das operações que tocam o host (exec / file ops). Protege contra loop do agente.
//! Nota: por ser tumbling, na virada da janela é possível uma rajada de até
//! 2×max em ~1s — aceitável para um breaker anti-loop (não é QoS fino).
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

pub struct RateLimiter {
    max_per_window: u32,
    state: Mutex<Window>,
}

struct Window {
    started: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new(max_per_window: u32) -> Self {
        RateLimiter {
            max_per_window,
            state: Mutex::new(Window {
                started: Instant::now(),
                count: 0,
            }),
        }
    }

    /// Tenta consumir um slot. `Ok(())` se permitido; `Err(msg)` se estourou.
    pub fn check(&self) -> Result<(), String> {
        if self.max_per_window == 0 {
            return Ok(()); // 0 = desabilitado
        }
        let mut w = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if w.started.elapsed() >= WINDOW {
            w.started = Instant::now();
            w.count = 0;
        }
        if w.count >= self.max_per_window {
            let wait = WINDOW.saturating_sub(w.started.elapsed()).as_secs();
            return Err(format!(
                "limite de {} operações/min atingido; aguarde ~{}s",
                self.max_per_window, wait
            ));
        }
        w.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estoura_no_limite() {
        let rl = RateLimiter::new(2);
        assert!(rl.check().is_ok());
        assert!(rl.check().is_ok());
        assert!(rl.check().is_err()); // 3ª na mesma janela
    }

    #[test]
    fn zero_desabilita() {
        let rl = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(rl.check().is_ok());
        }
    }
}
