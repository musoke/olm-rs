#[macro_use]
extern crate failure;
extern crate olm_util as util;
extern crate rand;
extern crate ring;
extern crate untrusted;

extern crate serde;
#[macro_use]
extern crate serde_derive;

use ring::agreement;
use std::fmt;

#[derive(Fail, Debug)]
pub enum OneTimeKeyError {
    #[fail(display = "Unable to generate key")] GenerationError,
    #[fail(display = "Unable to export key")] ExportError,
    #[fail(display = "Unable to import key")] ImportError,
}

// TODO: create non-exhaustive enums encapsulating the different possible key types.  This enum
// should "inherit" the `IdentityKey` and `IdentityKeyPriv` traits from the members.

// enum Algorithm {
//     Ed25519(Curve25519Pub),
//     #[doc(hidden)] __Nonexhaustive,
// }

/// Trait exposing methods on a public key
///
/// This should normally only be used in `olm::device` and `olm::ratchet`
pub trait IdentityKey {
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
pub trait IdentityKeyPriv {
    type Public: IdentityKey;

    // TODO: This should not be ephemeral; need updates to ring.  Then can pass a reference to
    // self instead of consuming.
    fn private_key(&self) -> agreement::EphemeralPrivateKey;
    fn public_key(&self) -> Self::Public;
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct Curve25519Pub {
    pub_key: Vec<u8>,
}

impl IdentityKey for Curve25519Pub {
    fn public_key(&self) -> untrusted::Input {
        untrusted::Input::from(&self.pub_key)
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
pub struct Curve25519Priv {
    // TODO: remove seed field; need updates to ring.
    seed: u8,
    private_key: agreement::EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl fmt::Debug for Curve25519Priv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Private identity key with public key {:?}",
            self.public_key()
        )
    }
}

impl Curve25519Priv {
    /// Create new identity key
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    pub fn generate() -> Result<Self, OneTimeKeyError> {
        unimplemented!()
    }

    /// This is a temporary hack
    pub fn generate_unrandom() -> Result<Self, OneTimeKeyError> {
        use rand;
        let seed = rand::random::<u8>();

        // TODO share one rng among all of lib
        let rng = ring::test::rand::FixedByteRandom { byte: seed };

        // Generate a new identity key
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| OneTimeKeyError::GenerationError)?;

        // Calculate corresponding public key
        let mut public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let public_key = &mut public_key[..private_key.public_key_len()];
        private_key
            .compute_public_key(public_key)
            .expect("can get public key from generated private key");

        Ok(Curve25519Priv {
            seed: seed,
            private_key: private_key,
            public_key: Vec::from(public_key),
        })
    }

    /// Create identity key from bytes
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    ///
    /// Currently unimplemented; ring only has ephemeral keys
    /// https://github.com/briansmith/ring/issues/331
    pub fn from_pkcs8(_input: untrusted::Input) -> Result<Self, OneTimeKeyError> {
        unimplemented!();
    }
}

impl IdentityKeyPriv for Curve25519Priv {
    type Public = Curve25519Pub;

    fn private_key(&self) -> agreement::EphemeralPrivateKey {
        let rng = ring::test::rand::FixedByteRandom { byte: self.seed };
        // Generate that same new one-time key
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .expect(
                "This call to agreement::EpemeralPrivateKey::generate will not be in final version",
            );

        private_key
    }

    fn public_key(&self) -> Self::Public {
        Curve25519Pub::from(self.public_key.clone())
    }
}
