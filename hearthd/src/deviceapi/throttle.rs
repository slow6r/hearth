//! Ограничитель попыток на `/claim`.
//!
//! # Зачем он появился
//!
//! Пока приглашение ехало внутри APK, подбирать было нечего: токен в 64
//! шестнадцатеричных знака никто не печатает руками. Код доступа человек вводит сам,
//! и `/claim` стал единственной дверью снаружи, куда можно стучаться словами.
//!
//! Шестидесяти бит кода хватает и без ограничителя — но «хватает по расчёту» и «никто
//! не молотит по двери» это разные вещи. Ограничитель здесь ради второго: он превращает
//! перебор в шум, который видно в алертах, и заодно бережёт узел от простой долбёжки.
//!
//! # Почему по адресу, а не глобально
//!
//! Глобальный счётчик означал бы, что один упрямый чужак закрывает вход всем: свои
//! люди заводятся редко и с разных адресов, чужак стучит с одного и часто. Поэтому
//! считаем по адресу, а глобально только шумим в алерты.
//!
//! # Чего он НЕ ловит
//!
//! Перебор с тысячи адресов сразу. Против такого работает длина кода, а не счётчик, и
//! это осознанный размен: городить здесь доказательство работы ради случая, который
//! против 60 бит всё равно бессмыслен, — значит усложнять единственный вход в контур.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// За какое время копятся неудачи.
const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Сколько неудач подряд терпим. Человек с бумажкой ошибётся раз-другой, не больше.
const MAX_FAILURES: u32 = 5;
/// Насколько закрываемся после того, как терпение кончилось.
const BLOCK: Duration = Duration::from_secs(60 * 60);
/// Сколько адресов помним. Больше — чистим протухшие: таблица не должна расти от того,
/// что по ней постучали с миллиона адресов.
const MAX_TRACKED: usize = 4096;

/// Что делать с пришедшим.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Пускать к проверке кода.
    Allow,
    /// Закрыто, и вот на сколько ещё.
    Blocked(Duration),
}

#[derive(Debug)]
struct Entry {
    failures: u32,
    window_started: Instant,
    blocked_until: Option<Instant>,
}

/// Счётчик неудачных попыток по адресам.
#[derive(Debug, Default)]
pub struct ClaimThrottle {
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

impl ClaimThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Пускать ли этот адрес к проверке кода.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Verdict {
        let entries = self.lock();
        match entries.get(&ip).and_then(|e| e.blocked_until) {
            Some(until) if until > now => Verdict::Blocked(until - now),
            _ => Verdict::Allow,
        }
    }

    /// Записать неудачу. `true`, если этой попыткой адрес только что закрылся, —
    /// вызывающий по этому решает, поднимать ли алерт: шуметь на каждой опечатке
    /// незачем, а на исчерпанном терпении — стоит.
    pub fn note_failure(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entries = self.lock();
        prune(&mut entries, now);
        let entry = entries.entry(ip).or_insert(Entry {
            failures: 0,
            window_started: now,
            blocked_until: None,
        });
        // Окно скользит целиком, а не по одной попытке: держать список отметок времени
        // ради точности на единицу — лишняя память на каждом адресе.
        if now.duration_since(entry.window_started) > WINDOW {
            entry.failures = 0;
            entry.window_started = now;
        }
        entry.failures += 1;
        if entry.failures >= MAX_FAILURES && entry.blocked_until.is_none_or(|u| u <= now) {
            entry.blocked_until = Some(now + BLOCK);
            entry.failures = 0;
            entry.window_started = now;
            return true;
        }
        false
    }

    /// Код подошёл — забываем накопленные неудачи.
    ///
    /// Но НЕ снимаем блокировку: иначе обладатель одного действующего кода
    /// перебирал бы чужие, вставляя между каждыми четырьмя попытками один успешный
    /// вход, и дверь не закрывалась бы никогда.
    pub fn note_success(&self, ip: IpAddr, now: Instant) {
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(&ip) {
            match entry.blocked_until {
                Some(until) if until > now => {
                    entry.failures = 0;
                    entry.window_started = now;
                }
                _ => {
                    entries.remove(&ip);
                }
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Entry>> {
        // Отравленный мьютекс — не повод ронять device API: внутри обычный HashMap,
        // и его худшее состояние после паники это лишняя запись о неудаче.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Выкинуть адреса, про которые больше нечего помнить.
fn prune(entries: &mut HashMap<IpAddr, Entry>, now: Instant) {
    if entries.len() < MAX_TRACKED {
        return;
    }
    entries.retain(|_, e| {
        e.blocked_until.is_some_and(|until| until > now)
            || now.duration_since(e.window_started) <= WINDOW
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn a_few_mistakes_are_forgiven() {
        let throttle = ClaimThrottle::new();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES - 1 {
            assert!(!throttle.note_failure(ip(1), now));
            assert_eq!(throttle.check(ip(1), now), Verdict::Allow);
        }
    }

    #[test]
    fn persistence_closes_the_door() {
        let throttle = ClaimThrottle::new();
        let now = Instant::now();
        let mut announced = false;
        for _ in 0..MAX_FAILURES {
            announced |= throttle.note_failure(ip(1), now);
        }
        assert!(announced, "закрытие двери должно быть объявлено ровно раз");
        assert!(matches!(throttle.check(ip(1), now), Verdict::Blocked(_)));
        // Соседа по сети это не касается.
        assert_eq!(throttle.check(ip(2), now), Verdict::Allow);
    }

    #[test]
    fn the_door_opens_again_later() {
        let throttle = ClaimThrottle::new();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES {
            throttle.note_failure(ip(1), now);
        }
        assert!(matches!(throttle.check(ip(1), now), Verdict::Blocked(_)));
        assert_eq!(throttle.check(ip(1), now + BLOCK), Verdict::Allow);
    }

    #[test]
    fn mistakes_spread_thin_never_add_up() {
        let throttle = ClaimThrottle::new();
        let mut now = Instant::now();
        for _ in 0..20 {
            assert!(!throttle.note_failure(ip(1), now));
            now += WINDOW + Duration::from_secs(1);
        }
        assert_eq!(throttle.check(ip(1), now), Verdict::Allow);
    }

    #[test]
    fn a_right_code_wipes_the_record() {
        let throttle = ClaimThrottle::new();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES - 1 {
            throttle.note_failure(ip(1), now);
        }
        throttle.note_success(ip(1), now);
        // Счёт начат заново: следующая неудача не должна закрывать дверь.
        assert!(!throttle.note_failure(ip(1), now));
    }

    #[test]
    fn a_right_code_does_not_open_a_closed_door() {
        // Иначе перебор чужих кодов идёт бесконечно: четыре промаха, один свой код,
        // снова четыре промаха — и MAX_FAILURES недостижимо никогда.
        let throttle = ClaimThrottle::new();
        let now = Instant::now();
        for _ in 0..MAX_FAILURES {
            throttle.note_failure(ip(1), now);
        }
        assert!(matches!(throttle.check(ip(1), now), Verdict::Blocked(_)));
        throttle.note_success(ip(1), now);
        assert!(
            matches!(throttle.check(ip(1), now), Verdict::Blocked(_)),
            "предъявление валидного кода не должно снимать блокировку"
        );
    }

    #[test]
    fn the_table_does_not_grow_without_bound() {
        let throttle = ClaimThrottle::new();
        let start = Instant::now();
        for i in 0..MAX_TRACKED + 100 {
            let addr = IpAddr::from((i as u32).to_be_bytes());
            throttle.note_failure(addr, start);
        }
        let later = start + WINDOW + Duration::from_secs(1);
        throttle.note_failure(ip(1), later);
        let len = throttle.lock().len();
        assert!(len <= MAX_TRACKED, "в таблице осталось {len} адресов");
    }
}
