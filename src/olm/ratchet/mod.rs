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
        Self {
            hashmap: HashMap::new(),
        }
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
    graph: (),
}

impl Ratchet {
    pub fn new(
        ident_alice: &identity_key::Curve25519Pub,
        one_time_alice: one_time_key::Curve25519Pub,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: identity_key::Curve25519Priv,
        one_time_bob: one_time_key::Curve25519Priv,
    ) -> Result<Self> {
        // TODO: change once non-ephemeral keys are available
        let (one_time_bob_1, one_time_bob_2) = one_time_bob.private_key();

        let mut secret_1 = agreement::agree_ephemeral(
            one_time_bob_1,
            &agreement::X25519,
            ident_alice.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_2 = agreement::agree_ephemeral(
            ident_bob.private_key(),
            &agreement::X25519,
            one_time_alice.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_3 = agreement::agree_ephemeral(
            one_time_bob_2,
            &agreement::X25519,
            one_time_alice.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut s = Vec::new();
        s.append(&mut secret_1);
        s.append(&mut secret_2);
        s.append(&mut secret_3);

        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let initial_salt: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, &[0]);

        let mut secret: [u8; 512] = [0; 512];
        hkdf::extract_and_expand(initial_salt, &s, "OLM_ROOT".as_bytes(), &mut secret);

        let (root, chain) = secret.split_at(256);

        Ok(Ratchet {
            id: RatchetId {},
            graph: (),
        })
    }

    pub fn import() -> Self {
        unimplemented!()
    }

    pub fn export() -> Self {
        unimplemented!()
    }
}

impl Ratchet {
    pub fn id(&self) -> RatchetId {
        self.id.clone()
    }
    pub fn advance_root(&mut self) {}
    pub fn advance_message(&mut self) {}
}
