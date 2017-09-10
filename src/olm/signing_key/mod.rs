use ring;
use ring::signature;
use untrusted;
use util;
use olm::errors::*;

// TODO: create non-exhaustive enums encapsulating the different possible key types.  This enum
// should "inherit" the SigningKey and SigningKeyPair traits from the members.


/// Trait exposing methods on a public key
///
/// This should normally only be used in `olm::device` and `olm::ratchet`
pub trait SigningKey {
    fn public_key(&self) -> untrusted::Input;

    /// Get base 64 encoded public key
    ///
    /// # Examples
    /// ```
    /// ```
    fn public_key_base64(&self) -> String {
        util::bin_to_base64(self.public_key().as_slice_less_safe())
    }

    /// Verify a signature
    ///
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()>;
}

/// Trait exposing methods on a private/pub key key pair
///
/// This should normally only be used in `olm::device` and `olm::ratchet`
pub trait SigningKeyPair {
    fn sign(&self, msg: &[u8]) -> signature::Signature;
    fn public_key(&self) -> untrusted::Input;
}

// impl SigningKey for SigningKeyPair {
//     fn public_key(&self) -> untrusted::Input {
//         self.public_key()
//     }
// }

pub struct Ed25519Pub {
    pub_key: Vec<u8>,
}

impl SigningKey for Ed25519Pub {
    fn public_key(&self) -> untrusted::Input {
        untrusted::Input::from(&self.pub_key)
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        Ok(signature::verify(
            &signature::ED25519,
            self.public_key(),
            untrusted::Input::from(msg),
            untrusted::Input::from(sig),
        )?)
    }
}

use std::convert::TryFrom;
impl<S> TryFrom<S> for Ed25519Pub
where
    S: Into<String>,
{
    type Error = Error;
    /// Convert base64 encoded strings to public keys
    ///
    /// Can fail if base64 is malformed.  No checks are done that the resulting public key is
    /// indeed a valid public key; this is done when verifying a signature.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(try_from)]
    /// use std::convert::TryFrom;
    ///
    /// let a = olm::olm::signing_key::Ed25519Pub
    ///         ::try_from("SogYyrkTldLz0BXP+GYWs0qaYacUI0RleEqNT8J3riQ");
    /// assert!(a.is_ok());
    ///
    /// let b = olm::olm::signing_key::Ed25519Pub
    ///         ::try_from("SogYyrkTldLz0BXP-GYWs0qaYacUI0RleEqNT8J3riQ");
    /// assert!(b.is_err());
    ///
    /// ```
    fn try_from(s: S) -> Result<Self> {
        Ok(Ed25519Pub {
            pub_key: util::base64_to_bin(&s.into())
                .chain_err::<_, ErrorKind>(|| ErrorKind::Base64DecodeError)
                .chain_err(|| "failed to read public signing key")?,
        })
    }
}

pub struct Ed25519Pair {
    pair: signature::Ed25519KeyPair,
}

impl Ed25519Pair {
    /// Create new signing key
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    pub fn generate() -> Result<Self> {
        // TODO share one rng among all of lib
        let rng = ring::rand::SystemRandom::new();

        // Generate a new signing key
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .chain_err(|| "Unable to generate signature key")?;
        // TODO Normally the application would store the PKCS#8 file persistently. Later it would
        // read the PKCS#8 file from persistent storage to use it.
        let signing_key_pair =
            signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8_bytes))?;

        Ok(Ed25519Pair {
            pair: signing_key_pair,
        })
    }

    /// Create signing key from btyes
    ///
    /// Should only be exposed via `LocalDevice::new()`?
    pub fn from_pkcs8(input: untrusted::Input) -> Result<Self> {
        Ok(Ed25519Pair {
            pair: signature::Ed25519KeyPair::from_pkcs8(input)
                .chain_err(|| "Failed to load private key")?,
        })
    }
}

impl SigningKeyPair for Ed25519Pair {
    fn sign(&self, msg: &[u8]) -> signature::Signature {
        self.pair.sign(msg)
    }

    fn public_key(&self) -> untrusted::Input {
        untrusted::Input::from(&self.pair.public_key_bytes())
    }
}
