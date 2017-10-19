use ring;
use ring::agreement;
use untrusted;
use util;
use olm::errors::*;
use std::collections::HashMap;
use std::fmt;

// TODO: create non-exhaustive enums encapsulating the different possible key types.  This enum
// should "inherit" the `OneTimeKey` and `OneTimeKeyPriv` traits from the members.

// enum Algorithm {
//     Ed25519(Curve25519Pub),
//     #[doc(hidden)] __Nonexhaustive,
// }

/// Trait exposing methods on a public key
///
/// This should normally only be used in `olm::device` and `olm::ratchet`
pub trait OneTimeKey {
    fn public_key(&self) -> untrusted::Input;

    /// Get base 64 encoded public key
    ///
    /// # Examples
    /// ```
    /// ```
    fn public_key_base64(&self) -> String {
        util::bin_to_base64(self.public_key().as_slice_less_safe())
    }
}

/// Trait exposing methods on a private key
///
/// This should normally only be used in `olm::device` and `olm::ratchet`
pub trait OneTimeKeyPriv {
    type Public: OneTimeKey;

    // TODO: This should not be ephemeral; need updates to ring.  Then can pass a reference to
    // self instead of consuming.
    fn private_key(&self) -> agreement::EphemeralPrivateKey;
    fn public_key(&self) -> Self::Public;
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct Curve25519Pub {
    pub_key: Vec<u8>,
}

impl OneTimeKey for Curve25519Pub {
    fn public_key(&self) -> untrusted::Input {
        untrusted::Input::from(&self.pub_key)
    }
}

impl Into<Vec<u8>> for Curve25519Pub {
    fn into(self) -> Vec<u8> {
        self.pub_key
    }
}

impl From<Vec<u8>> for Curve25519Pub {
    /// Create public Curve25519 key from bytes
    ///
    /// This is unchecked until the public key is used to complete an agreement
    ///
    fn from(v: Vec<u8>) -> Curve25519Pub {
        Curve25519Pub { pub_key: v }
    }
}

/// Private one-time key
///
/// Currently is ephemeral; should be persistent.  See
/// https://github.com/briansmith/ring/issues/331
///
/// Since we need to use each private key twice in the course of the agreement, store a seed from
/// which the private key can be regenerated.  Hopefully this will be fixable in the near future.
pub struct Curve25519Priv {
    // TODO: remove need for this seed
    seed: u8,
    private_key: agreement::EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl fmt::Debug for Curve25519Priv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Private one time key with public key {:?}",
            self.public_key()
        )
    }
}

impl Curve25519Priv {
    /// Create new one-time key
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    pub fn generate() -> Result<Self> {
        unimplemented!()
    }

    /// This is a temporary hack
    pub fn generate_unrandom() -> Result<Self> {

        use rand;
        let seed = rand::random::<u8>();

        // TODO share one rng among all of lib
        let rng = ring::test::rand::FixedByteRandom { byte: seed };

        // Generate a new one-time key
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .chain_err(|| "Unable to generate one-time key")?;

        // Calculate corresponding public key
        let mut public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let public_key = &mut public_key[..private_key.public_key_len()];
        private_key.compute_public_key(public_key).expect(
            "can get public key from generated private key",
        );

        Ok(Curve25519Priv {
            seed: seed,
            private_key: private_key,
            public_key: Vec::from(public_key),
        })
    }

    /// Create one-time key from bytes
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    ///
    /// Currently unimplemented; ring only has ephemeral keys
    /// https://github.com/briansmith/ring/issues/331
    pub fn from_pkcs8(_input: untrusted::Input) -> Result<Self> {
        unimplemented!();
    }
}

impl OneTimeKeyPriv for Curve25519Priv {
    type Public = Curve25519Pub;

    fn private_key(&self) -> agreement::EphemeralPrivateKey {
        let rng = ring::test::rand::FixedByteRandom { byte: self.seed };
        // Generate that same new one-time key
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .chain_err(|| "Unable to generate one-time key")
            .expect(
                "This call to agreement::EpemeralPrivateKey::generate will not be in final version",
            );

        private_key
    }

    fn public_key(&self) -> Self::Public {
        Curve25519Pub::from(self.public_key.clone())
    }
}

pub struct Store {
    // TODO value should be enum of private key types
    pub hashmap: HashMap<Curve25519Pub, Curve25519Priv>,
}

impl Store {
    pub const DEFAULT_NUM_ONE_TIME_KEY_PAIRS: usize = 20;

    /// Generate one time keys
    ///
    /// ```
    /// let s = olm::olm::one_time_key::Store::generate().expect("Can generate onetime key store");
    /// ```
    pub fn generate() -> Result<Self> {
        let mut store =
            Store { hashmap: HashMap::with_capacity(Self::DEFAULT_NUM_ONE_TIME_KEY_PAIRS) };

        for _ in 0..Self::DEFAULT_NUM_ONE_TIME_KEY_PAIRS {
            // TODO generate an actual random key
            let s = Curve25519Priv::generate_unrandom()?;
            let p = s.public_key();
            store.insert(p, s);
        }

        Ok(store)
    }

    /// Get Vec of one-time keys
    ///
    /// Used for updating server list of available one-time keys on server.
    ///
    /// # Examples
    /// ```
    /// let s = olm::olm::one_time_key::Store::generate().expect("Store creation should succeed");
    /// assert!(s.get_keys().pop().is_some());
    /// ```
    pub fn get_keys(&self) -> Vec<&Curve25519Pub> {
        self.hashmap.keys().collect()
    }

    /// Check if a one-time key is in the store
    ///
    /// # Examples
    ///
    /// ```
    /// let s = olm::olm::one_time_key::Store::generate().expect("Store creation should succeed");
    /// let p = s.get_keys().pop().expect("New store should have keys");
    ///
    /// assert!(s.contains_key(p));
    /// ```
    pub fn contains_key(&self, k: &Curve25519Pub) -> bool {
        self.hashmap.contains_key(k)
    }

    /// Add a new one time key to store
    // TODO: check general signature of HashMap::insert
    pub fn insert(&mut self, p: Curve25519Pub, s: Curve25519Priv) {
        self.hashmap.insert(p, s);
    }
}


#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn consistent_one_time() {

        let a = Curve25519Priv::generate_unrandom().unwrap();
        let b = Curve25519Priv::generate_unrandom().unwrap();

        let a_pub = a.public_key();
        let b_pub = b.public_key();

        assert_ne!(a_pub.public_key(), b_pub.public_key());

        let dh1 = agreement::agree_ephemeral(
            a.private_key(),
            &agreement::X25519,
            b_pub.public_key(),
            Error::from("asdf"),
            |d| Ok(d.to_vec()),
        ).unwrap();

        let dh2 = agreement::agree_ephemeral(
            a.private_key(),
            &agreement::X25519,
            b_pub.public_key(),
            Error::from("asdf"),
            |d| Ok(d.to_vec()),
        ).unwrap();

        assert_eq!(dh1, dh2);
    }

}
