//! Session keys, replay protection and the client side of the handshake
//! (see `edup_common::aead`). The sender thread only reads the current
//! session; the receiver thread owns everything else and drives handshakes.
use edup_common::{
    aead::{self, Cipher},
    crypto::{self, Key},
    key::derive_key,
    wire::{self, HANDSHAKE_LEN, HDR_LEN, Header},
};
use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

/// Retransmit INIT this often until a RESPONSE arrives.
pub const HANDSHAKE_RETRY: Duration = Duration::from_secs(1);
/// A KEEPALIVE left unanswered this long means the server lost the session
/// (for example after a reload): handshake again.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Rekey long before the 48-bit packet counter could run out.
const REKEY_AFTER: u64 = wire::MAX_COUNTER - (1 << 32);
/// 256 slots of 16 counters: server CPUs may interleave a user's packets.
const WINDOW_SLOTS: usize = 256;

pub struct Session {
    cipher: Cipher,
    pub phase: u8,
    tx: AtomicU64,
}

impl Session {
    fn new(key: &Key, phase: u8) -> Self {
        Self {
            cipher: Cipher::new(key),
            phase,
            // Counter 0 is never used by clients.
            tx: AtomicU64::new(1),
        }
    }

    fn next(&self) -> Option<u64> {
        let counter = self.tx.fetch_add(1, Relaxed);
        (counter <= wire::MAX_COUNTER).then_some(counter)
    }

    fn exhausted(&self) -> bool {
        self.tx.load(Relaxed) > REKEY_AFTER
    }

    /// Compact and seal an IP packet placed at `pkt[HDR_LEN..]`.
    pub fn seal_data(&self, user: i64, pkt: &mut [u8]) -> Option<usize> {
        aead::seal_data(&self.cipher, user, self.phase, self.next()?, pkt, true)
    }

    fn keepalive(&self, user: i64) -> Option<[u8; HDR_LEN]> {
        let header = Header {
            user,
            typ: wire::TYPE_KEEPALIVE,
            phase: self.phase,
            counter: self.next()?,
        };
        Some(aead::keepalive(&self.cipher, header, wire::TO_SERVER))
    }
}

/// The user's identity and current session, shared by both threads.
pub struct Link {
    pub user: i64,
    key: Key,
    current: RwLock<Option<Arc<Session>>>,
}

impl Link {
    pub fn new(user: i64, password: &str) -> Self {
        Self {
            user,
            key: derive_key(password),
            current: RwLock::new(None),
        }
    }

    /// The session to seal with, once a handshake completed.
    pub fn current(&self) -> Option<Arc<Session>> {
        self.current.read().unwrap().clone()
    }

    fn install(&self, session: Arc<Session>) {
        *self.current.write().unwrap() = Some(session);
    }
}

/// Accepts each counter at most once (see `crypto::replay_update`).
struct Window(Box<[u64; WINDOW_SLOTS]>);

impl Window {
    fn new() -> Self {
        Self(Box::new([0; WINDOW_SLOTS]))
    }

    fn accept(&mut self, counter: u64) -> bool {
        let slot = &mut self.0[crypto::replay_index(counter, WINDOW_SLOTS)];
        match crypto::replay_update(*slot, counter) {
            Some(value) => {
                *slot = value;
                true
            }
            None => false,
        }
    }
}

pub enum Outgoing {
    Init([u8; HANDSHAKE_LEN]),
    Keepalive([u8; HDR_LEN]),
}

impl Outgoing {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Init(p) => p,
            Self::Keepalive(p) => p,
        }
    }
}

pub enum Received {
    /// Authenticated data; the plaintext compact packet is at `HDR_LEN..`.
    Data(Header),
    Keepalive,
    Established(u8),
    Dropped,
}

/// Receive-side state, owned by the receiving thread.
pub struct Receiver {
    /// Sessions by key phase: after a rekey, packets the server sealed with
    /// the previous session still open.
    sessions: [Option<(Arc<Session>, Window)>; 2],
    /// K1 of the INIT awaiting a RESPONSE, and when that INIT was sent.
    pending: Option<(Key, Instant)>,
    /// The oldest KEEPALIVE sent since the last authenticated packet.
    probe: Option<Instant>,
    next_keepalive: Instant,
}

impl Receiver {
    pub fn new(now: Instant) -> Self {
        Self {
            sessions: [None, None],
            pending: None,
            probe: None,
            next_keepalive: now,
        }
    }

    /// What to send now, if anything: INIT while there is no working session
    /// (retransmitted until answered), otherwise KEEPALIVE on its schedule.
    /// Data keeps flowing on the old session while a new one is negotiated.
    pub fn poll(&mut self, link: &Link, now: Instant, interval: Duration) -> Option<Outgoing> {
        let current = link.current();
        let lost = self
            .probe
            .is_some_and(|sent| now.duration_since(sent) >= REPLY_TIMEOUT);
        if current.as_ref().is_none_or(|s| s.exhausted()) || lost {
            if self
                .pending
                .is_some_and(|(_, sent)| now.duration_since(sent) < HANDSHAKE_RETRY)
            {
                return None;
            }
            let mut nonce = [0; wire::NONCE_LEN];
            getrandom::fill(&mut nonce).expect("system random number generator");
            let (packet, k1) = aead::init(&link.key, link.user, &nonce);
            self.pending = Some((k1, now));
            return Some(Outgoing::Init(packet));
        }
        if now < self.next_keepalive {
            return None;
        }
        self.next_keepalive = now + interval;
        self.probe.get_or_insert(now);
        current?.keepalive(link.user).map(Outgoing::Keepalive)
    }

    /// Authenticate one datagram and decrypt it in place.
    pub fn open(&mut self, link: &Link, data: &mut [u8], now: Instant) -> Received {
        let Some(header) = Header::decode(data) else {
            return Received::Dropped;
        };
        if header.user != link.user {
            return Received::Dropped;
        }
        if header.typ == wire::TYPE_RESPONSE {
            let Some((k1, _)) = self.pending else {
                return Received::Dropped;
            };
            let Some((key, phase)) = aead::open_response(&k1, data) else {
                return Received::Dropped;
            };
            let session = Arc::new(Session::new(&key, phase));
            self.sessions[phase as usize] = Some((session.clone(), Window::new()));
            link.install(session);
            self.pending = None;
            self.probe = None;
            // The server switches to the new session on its first packet.
            self.next_keepalive = now;
            return Received::Established(phase);
        }
        let Some((session, window)) = self.sessions[header.phase as usize].as_mut() else {
            return Received::Dropped;
        };
        // Replay is checked only after authentication: a forgery must not
        // be able to advance the window.
        if session.cipher.open(wire::TO_CLIENT, data).is_none() || !window.accept(header.counter) {
            return Received::Dropped;
        }
        self.probe = None;
        match header.typ {
            wire::TYPE_KEEPALIVE if data.len() == HDR_LEN => Received::Keepalive,
            wire::TYPE_DATA | wire::TYPE_IPV6 => Received::Data(header),
            _ => Received::Dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal server: answers INIT, opens and seals session packets.
    struct Server {
        key: Key,
        session: Option<(Cipher, u8, u64)>,
        phase: u8,
    }
    impl Server {
        fn respond(&mut self, init: &[u8]) -> [u8; HANDSHAKE_LEN] {
            let k1 = aead::open_init(&self.key, init).unwrap();
            self.phase ^= 1;
            let (resp, key) = aead::response(&k1, 7, self.phase, &[self.phase; 16]);
            self.session = Some((Cipher::new(&key), self.phase, 1));
            resp
        }
        fn keepalive(&mut self) -> [u8; HDR_LEN] {
            let (cipher, phase, tx) = self.session.as_mut().unwrap();
            *tx += 1;
            let header = Header {
                user: 7,
                typ: wire::TYPE_KEEPALIVE,
                phase: *phase,
                counter: *tx,
            };
            aead::keepalive(cipher, header, wire::TO_CLIENT)
        }
    }

    #[test]
    fn handshake_keepalive_replay_rekey_and_timeouts() {
        let link = Link::new(7, "password");
        let mut server = Server {
            key: derive_key("password"),
            session: None,
            phase: 0,
        };
        let start = Instant::now();
        let mut rx = Receiver::new(start);
        let interval = Duration::from_secs(15);
        let Some(Outgoing::Init(init)) = rx.poll(&link, start, interval) else {
            panic!("no session: INIT first");
        };
        assert!(rx.poll(&link, start, interval).is_none(), "INIT is paced");
        let retry = start + HANDSHAKE_RETRY;
        let Some(Outgoing::Init(init2)) = rx.poll(&link, retry, interval) else {
            panic!("INIT retransmitted");
        };
        assert_ne!(init, init2, "a fresh nonce per attempt");
        // A RESPONSE to the superseded INIT does not authenticate.
        let mut stale = server.respond(&init);
        assert!(matches!(
            rx.open(&link, &mut stale, retry),
            Received::Dropped
        ));
        let mut resp = server.respond(&init2);
        let mut forged = resp;
        forged[HDR_LEN] ^= 1;
        assert!(matches!(
            rx.open(&link, &mut forged, retry),
            Received::Dropped
        ));
        assert!(matches!(
            rx.open(&link, &mut resp, retry),
            Received::Established(0)
        ));
        assert!(matches!(
            rx.open(&link, &mut resp.clone(), retry),
            Received::Dropped
        ));
        // Confirmation KEEPALIVE right away, then on schedule.
        assert!(matches!(
            rx.poll(&link, retry, interval),
            Some(Outgoing::Keepalive(_))
        ));
        assert!(rx.poll(&link, retry, interval).is_none());
        let mut reply = server.keepalive();
        let copy = reply;
        assert!(matches!(
            rx.open(&link, &mut reply, retry),
            Received::Keepalive
        ));
        assert!(matches!(
            rx.open(&link, &mut copy.clone(), retry),
            Received::Dropped
        ));
        let mut other_user = copy;
        other_user[7] ^= 1;
        assert!(matches!(
            rx.open(&link, &mut other_user, retry),
            Received::Dropped
        ));
        // An unanswered KEEPALIVE leads to a new handshake after the timeout.
        let later = retry + interval;
        assert!(matches!(
            rx.poll(&link, later, interval),
            Some(Outgoing::Keepalive(_))
        ));
        assert!(
            rx.poll(&link, later + REPLY_TIMEOUT / 2, interval)
                .is_none()
        );
        let lost = later + REPLY_TIMEOUT;
        let Some(Outgoing::Init(init3)) = rx.poll(&link, lost, interval) else {
            panic!("server stopped answering: new handshake");
        };
        // Packets sealed with the old session still open during the rekey.
        let mut in_flight = server.keepalive();
        let old_phase = server.phase;
        let mut resp = server.respond(&init3);
        assert!(matches!(
            rx.open(&link, &mut resp, lost),
            Received::Established(1)
        ));
        assert_eq!(link.current().unwrap().phase, 1);
        assert_ne!(old_phase, server.phase);
        assert!(matches!(
            rx.open(&link, &mut in_flight, lost),
            Received::Keepalive
        ));
    }

    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut window = Window::new();
        // Newest first: everything within the last 256 blocks of 16 is new.
        let oldest_block = (4999 >> 4) - (WINDOW_SLOTS as u64 - 1);
        for counter in (1..5000).rev() {
            assert_eq!(
                window.accept(counter),
                counter >> 4 >= oldest_block,
                "{counter}"
            );
        }
        for counter in 5000..6000 {
            assert!(window.accept(counter));
            assert!(!window.accept(counter));
        }
    }
}
