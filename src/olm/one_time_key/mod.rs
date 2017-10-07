use ring;
use ring::agreement;
use untrusted;
use util;
use olm::errors::*;
use std::collections::HashMap;

// TODO: create non-exhaustive enums encapsulating the different possible key types.  This enum
// should "inherit" the `OneTimeKey` and `OneTimeKeyPriv` traits from the members.

// enum OneTimeKeyTypes {
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
///
/// Require that the type also implements `OneTimeKey` so that one can get the public key.
pub trait OneTimeKeyPriv: OneTimeKey {
    // TODO: This should not be ephemeral; need updates to ring.  Then can pass a reference to
    // self instead of consuming.
    fn private_key(
        self,
    ) -> (
        agreement::EphemeralPrivateKey,
        agreement::EphemeralPrivateKey,
    );
}

#[derive(PartialEq, Eq, Hash)]
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

use std::convert::TryFrom;
impl<S> TryFrom<S> for Curve25519Pub
where
    S: Into<String>,
{
    type Error = Error;
    /// Convert base64 encoded strings to public keys
    ///
    /// Can fail if base64 is malformed.  No checks are done that the resulting public key is
    /// indeed a valid public key.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(try_from)]
    /// use std::convert::TryFrom;
    ///
    /// let a = olm::olm::one_time_key::Curve25519Pub
    ///         ::try_from("JGLn/yafz74HB2AbPLYJWIVGnKAtqECOBf11yyXac2Y");
    /// assert!(a.is_ok());
    ///
    /// let b = olm::olm::one_time_key::Curve25519Pub
    ///         ::try_from("JGLn_yafz74HB2AbPLYJWIVGnKAtqECOBf11yyXac2Y");
    /// assert!(b.is_err());
    ///
    /// ```
    fn try_from(s: S) -> Result<Self> {
        Ok(Curve25519Pub {
            pub_key: util::base64_to_bin(&s.into())
                .chain_err::<_, ErrorKind>(|| ErrorKind::Base64DecodeError)
                .chain_err(|| "failed to read public identity key")?,
        })
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

/// Private identity key
///
/// Currently is ephemeral; should be persistent.  See
/// https://github.com/briansmith/ring/issues/331
///
/// Since we need to use each private key twice in the course of the agreement, store 2 identical
/// copies in a tuple.  They are identical because for now they aren't even random.  Hopefully this
/// will be fixable in the near future.
pub struct Curve25519Priv {
    private_key: (
        agreement::EphemeralPrivateKey,
        agreement::EphemeralPrivateKey,
    ),
    public_key: Vec<u8>,
}

impl Curve25519Priv {
    /// Create new identity key
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    pub fn generate() -> Result<Self> {
        unimplemented!()
    }

    pub fn generate_fixed(i: u8) -> Result<(Curve25519Pub, Self)> {
        // TODO share one rng among all of lib
        let rng = ring::test::rand::FixedByteRandom { byte: i };

        // Generate a new identity key
        let private_key_1 = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .chain_err(|| "Unable to generate identity key")?;
        let private_key_2 = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .chain_err(|| "Unable to generate identity key")?;


        // Calculate corresponding public key
        let mut public_key_1 = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let public_key_1 = &mut public_key_1[..private_key_1.public_key_len()];
        private_key_1
            .compute_public_key(public_key_1)
            .expect("can get public key from generated private key");
        let mut public_key_2 = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let public_key_2 = &mut public_key_2[..private_key_2.public_key_len()];
        private_key_2
            .compute_public_key(public_key_2)
            .expect("can get public key from generated private key");

        Ok((
            Curve25519Pub::from(Vec::from(public_key_1)),
            Curve25519Priv {
                private_key: (private_key_1, private_key_2),
                public_key: Vec::from(public_key_2),
            },
        ))
    }

    /// Create identity key from bytes
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    ///
    /// Currently unimplemented; ring only has ephemeral keys
    /// https://github.com/briansmith/ring/issues/331
    pub fn from_pkcs8(_input: untrusted::Input) -> Result<Self> {
        unimplemented!();
    }
}

impl OneTimeKey for Curve25519Priv {
    fn public_key(&self) -> untrusted::Input {
        untrusted::Input::from(&self.public_key)
    }
}

impl OneTimeKeyPriv for Curve25519Priv {
    fn private_key(
        self,
    ) -> (
        agreement::EphemeralPrivateKey,
        agreement::EphemeralPrivateKey,
    ) {
        self.private_key
    }
}

const DEFAULT_NUM_ONE_TIME_KEY_PAIRS: usize = 5;

pub struct Store {
    // TODO value should be enum of private key types
    pub hashmap: HashMap<Curve25519Pub, Curve25519Priv>,
}

impl Store {
    /// Generate one time keys
    ///
    /// ```
    /// let s = olm::olm::one_time_key::Store::generate().expect("Can generate onetime key store");
    /// ```
    pub fn generate() -> Result<Self> {
        let mut store = Store {
            hashmap: HashMap::with_capacity(DEFAULT_NUM_ONE_TIME_KEY_PAIRS),
        };

        for i in 0..DEFAULT_NUM_ONE_TIME_KEY_PAIRS {
            // TODO generate an actual random key
            let (p, s) = Curve25519Priv::generate_fixed(i as u8)?;
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
