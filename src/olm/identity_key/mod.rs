use ring;
use ring::agreement;
use untrusted;
use util;
use olm::errors::*;

// TODO: create non-exhaustive enums encapsulating the different possible key types.  This enum
// should "inherit" the `IdentityKey` and `IdentityKeyPriv` traits from the members.

// enum IdentityKeyTypes {
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
///
/// Require that the type also implements IdentityKey so that one can get the public key.
pub trait IdentityKeyPriv: IdentityKey {
    // TODO: This should not be ephemeral; need updates to ring.  Then can pass a reference to
    // self instead of consuming.
    fn private_key(self) -> agreement::EphemeralPrivateKey;
}

pub struct Curve25519Pub {
    pub_key: Vec<u8>,
}

impl IdentityKey for Curve25519Pub {
    fn public_key(&self) -> untrusted::Input {
        untrusted::Input::from(&self.pub_key)
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
    /// let a = olm::olm::identity_key::Curve25519Pub
    ///         ::try_from("JGLn/yafz74HB2AbPLYJWIVGnKAtqECOBf11yyXac2Y");
    /// assert!(a.is_ok());
    ///
    /// let b = olm::olm::identity_key::Curve25519Pub
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
pub struct Curve25519Priv {
    private_key: agreement::EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl Curve25519Priv {
    /// Create new identity key
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    pub fn generate() -> Result<Self> {
        // TODO share one rng among all of lib
        let rng = ring::rand::SystemRandom::new();

        // Generate a new identity key
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .chain_err(|| "Unable to generate identity key")?;

        // Calculate corresponding public key
        let mut public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let public_key = &mut public_key[..private_key.public_key_len()];
        private_key
            .compute_public_key(public_key)
            .expect("can get public key from generated private key");

        Ok(Curve25519Priv {
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
    pub fn from_pkcs8(_input: untrusted::Input) -> Result<Self> {
        unimplemented!();
    }
}

impl IdentityKey for Curve25519Priv {
    fn public_key(&self) -> untrusted::Input {
        untrusted::Input::from(&self.public_key)
    }
}

impl IdentityKeyPriv for Curve25519Priv {
    fn private_key(self) -> agreement::EphemeralPrivateKey {
        self.private_key
    }
}
