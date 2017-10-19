use ring;
use ring::agreement;
use ring::{hkdf, hmac};
use std::collections::HashMap;
use olm::errors::*;
use olm::{identity_key, one_time_key};
use olm::one_time_key::{OneTimeKey, OneTimeKeyPriv};
use olm::identity_key::{IdentityKey, IdentityKeyPriv};


pub struct Store {
    hashmap: HashMap<RatchetId, Ratchet>,
}

impl Store {
    pub fn new() -> Self {
        Self { hashmap: HashMap::new() }
    }

    pub fn import() -> Self {
        unimplemented!()
    }

    pub fn export() -> Self {
        unimplemented!()
    }
}

impl Store {
    fn insert(&mut self, r: Ratchet) {
        self.hashmap.insert(r.id(), r);
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct RatchetId {}

#[derive(Debug)]
struct Ratchet {
    id: RatchetId,
    algorithm: (),
    state: State,
}

#[derive(Debug)]
#[derive(Default)]
struct State {
    // TODO: Should not be a tuple once ring has non-ephemeral keys
    dh_self: Option<one_time_key::Curve25519Priv>,
    dh_remote: Option<one_time_key::Curve25519Pub>,
    root_key: [u8; 32],
    chain_key_sending: Option<[u8; 32]>,
    chain_key_recieve: Option<[u8; 32]>,
    n_sending: u64,
    n_recieve: u64,
    n_previous: u64,
    mk_skipped: HashMap<(u64, u64), ()>,
}

impl Ratchet {
    pub fn init_sending(
        ident_alice: identity_key::Curve25519Priv,
        one_time_alice: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: &identity_key::Curve25519Pub,
        one_time_bob: one_time_key::Curve25519Pub,
        dh_bob: one_time_key::Curve25519Pub,
    ) -> Result<Self> {

        let state =
            State::init_sending(ident_alice, one_time_alice, ident_bob, one_time_bob, dh_bob)
                .chain_err(|| "Failed to initialize ratchet for sending")?;

        Ok(Ratchet {
            id: RatchetId {},
            algorithm: (),
            state: state,
        })
    }

    pub fn init_recieving(
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: identity_key::Curve25519Priv,
        one_time_bob: one_time_key::Curve25519Priv,
        ident_alice: &identity_key::Curve25519Pub,
        one_time_alice: one_time_key::Curve25519Pub,
        dh_bob: one_time_key::Curve25519Priv,
    ) -> Result<Self> {

        let state =
            State::init_recieving(ident_bob, one_time_bob, ident_alice, one_time_alice, dh_bob)
                .chain_err(|| "Failed to initialize ratchet for receiving")?;

        Ok(Ratchet {
            id: RatchetId {},
            algorithm: (),
            state: state,
        })
    }

    pub fn encrypt(&mut self, plaintext: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
        let enc = self.state.encrypt(plaintext)?;

        unimplemented!()
    }
}

impl State {
    pub fn init_sending(
        ident_alice: identity_key::Curve25519Priv,
        one_time_alice: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: &identity_key::Curve25519Pub,
        one_time_bob: one_time_key::Curve25519Pub,
        dh_bob: one_time_key::Curve25519Pub,
    ) -> Result<Self> {
        let mut state: State = Default::default();

        let dh_self_priv = one_time_key::Curve25519Priv::generate_unrandom()?;
        state.dh_self = Some(dh_self_priv);
        state.dh_remote = Some(dh_bob);

        let shared_secret =
            State::x3dh_local(ident_alice, one_time_alice, ident_bob, one_time_bob)?;
        let (root, chain) = State::kdf_rk_init(shared_secret);

        state.root_key = root;
        state.chain_key_sending = Some(chain);

        Ok(state)
    }

    pub fn init_recieving(
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: identity_key::Curve25519Priv,
        one_time_bob: one_time_key::Curve25519Priv,
        ident_alice: &identity_key::Curve25519Pub,
        one_time_alice: one_time_key::Curve25519Pub,
        dh_bob: one_time_key::Curve25519Priv,
    ) -> Result<Self> {
        let mut state: State = Default::default();

        state.dh_self = Some(dh_bob);

        let shared_secret =
            State::x3dh_remote(ident_bob, one_time_bob, ident_alice, one_time_alice)?;
        let (root, chain) = State::kdf_rk_init(shared_secret);

        state.root_key = root;
        state.chain_key_recieve = Some(chain);

        Ok(state)
    }

    fn x3dh_local(
        ident_local: identity_key::Curve25519Priv,
        one_time_local: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_remote: &identity_key::Curve25519Pub,
        one_time_remote: one_time_key::Curve25519Pub,
    ) -> Result<Vec<u8>> {
        // TODO: change once non-ephemeral keys are available

        let mut secret_1 = agreement::agree_ephemeral(
            ident_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_2 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            ident_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_3 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut s = Vec::new();
        s.append(&mut secret_1);
        s.append(&mut secret_2);
        s.append(&mut secret_3);

        Ok(s)
    }

    fn x3dh_remote(
        ident_local: identity_key::Curve25519Priv,
        one_time_local: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_remote: &identity_key::Curve25519Pub,
        one_time_remote: one_time_key::Curve25519Pub,
    ) -> Result<Vec<u8>> {
        // TODO: change once non-ephemeral keys are available

        let mut secret_1 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            ident_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_2 = agreement::agree_ephemeral(
            ident_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_3 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut s = Vec::new();
        s.append(&mut secret_1);
        s.append(&mut secret_2);
        s.append(&mut secret_3);

        Ok(s)
    }

    /// Derive the initial root key and chain key
    fn kdf_rk_init(shared_secret: Vec<u8>) -> ([u8; 32], [u8; 32]) {
        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let initial_salt: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, &[0]);

        let mut secret: [u8; 64] = [0; 64];
        hkdf::extract_and_expand(
            initial_salt,
            &shared_secret,
            "OLM_ROOT".as_bytes(),
            &mut secret,
        );

        let mut root: [u8; 32] = [0; 32];
        let mut chain: [u8; 32] = [0; 32];
        root.copy_from_slice(&secret[0..32]);
        chain.copy_from_slice(&secret[32..64]);

        (root, chain)
    }

    /// Advance the root key and return the new root key and chain key
    pub fn kdf_rk(&mut self, dh_out: Vec<u8>) -> ([u8; 32], [u8; 32]) {
        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let salt: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, &self.root_key);

        let mut secret: [u8; 512] = [0; 512];
        hkdf::extract_and_expand(salt, &dh_out, b"OLM_RATCHET", &mut secret);

        let mut root: [u8; 32] = [0; 32];
        let mut chain: [u8; 32] = [0; 32];

        root.copy_from_slice(&secret[0..32]);
        chain.copy_from_slice(&secret[32..64]);

        (root, chain)
    }

    pub fn encrypt(&mut self, plaintext: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {

        let mk = State::kdf_mk(&self.chain_key_sending.expect(
            "Should have a sending chain",
        ));
        self.chain_key_sending = Some(State::kdf_ck(
            self.chain_key_sending.expect("Should have a sending chain"),
        ));

        self.n_sending += 1;

        unimplemented!()
    }

    /// Derive message key from chain key
    fn kdf_mk(ck: &[u8; 32]) -> [u8; 32] {
        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let c: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, ck);

        let data: [u8; 1] = [0x01];

        let sig = hmac::sign(c, &data);

        let mut mk = [0; 32];
        mk.copy_from_slice(sig.as_ref());

        mk
    }

    /// Derive chain key from previous chain key
    ///
    /// Note that this consumes the input chain key whereas `kdf_mk` does not.
    fn kdf_ck(ck: [u8; 32]) -> [u8; 32] {
        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let c: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, &ck);

        let data: [u8; 1] = [0x02];

        let sig = hmac::sign(c, &data);

        let mut ck = [0; 32];
        ck.copy_from_slice(sig.as_ref());

        ck
    }
}

impl Ratchet {
    pub fn id(&self) -> RatchetId {
        self.id.clone()
    }
}

#[cfg(test)]
mod test {

    use olm::{identity_key, one_time_key};
    use olm::identity_key::{IdentityKey, IdentityKeyPriv};
    use olm::one_time_key::{OneTimeKey, OneTimeKeyPriv};
    use olm::ratchet::Ratchet;

    fn generate_ratchets() -> (Ratchet, Ratchet) {

        let alice_ident_priv = identity_key::Curve25519Priv::generate_unrandom().unwrap();
        let alice_ident_pub = alice_ident_priv.public_key();
        let bob_ident_priv = identity_key::Curve25519Priv::generate_unrandom().unwrap();
        let bob_ident_pub = bob_ident_priv.public_key();

        let alice_one_time_priv = one_time_key::Curve25519Priv::generate_unrandom().unwrap();
        let alice_one_time_pub = alice_one_time_priv.public_key();
        let bob_one_time_priv = one_time_key::Curve25519Priv::generate_unrandom().unwrap();
        let bob_one_time_pub = bob_one_time_priv.public_key();

        let dh_bob_priv = one_time_key::Curve25519Priv::generate_unrandom().unwrap();

        let ratchet_alice = Ratchet::init_sending(
            alice_ident_priv,
            alice_one_time_priv,
            &bob_ident_pub,
            bob_one_time_pub,
            dh_bob_priv.public_key(),
        ).unwrap();

        let ratchet_bob = Ratchet::init_recieving(
            bob_ident_priv,
            bob_one_time_priv,
            &alice_ident_pub,
            alice_one_time_pub,
            dh_bob_priv,
        ).unwrap();

        (ratchet_alice, ratchet_bob)
    }

    // Check that the ratchet generated by each party matches
    #[test]
    fn initial_state_match() {

        let (ratchet_alice, ratchet_bob) = generate_ratchets();

        assert_eq!(ratchet_alice.state.root_key, ratchet_bob.state.root_key);
        assert_eq!(
            ratchet_alice.state.chain_key_sending,
            ratchet_bob.state.chain_key_recieve
        );
    }

}
