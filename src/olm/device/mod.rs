use std::fmt;
use ring;
use ring::{agreement, rand, signature};
use untrusted;
use std::collections::HashMap;
use olm::errors::*;

#[derive(Debug)]
pub struct DeviceId {
    // TODO: Any requirements on format? Spec just says string; most examples seem to be ~10 upper
    // case letters
    id: String,
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl<S> From<S> for DeviceId
where
    S: Into<String>,
{
    /// # Examples
    ///
    /// ```
    /// let d = ::olm::olm::device::DeviceId::from("DEVID");
    /// let s: String = d.to_string();
    /// ```
    fn from(s: S) -> DeviceId {
        DeviceId { id: s.into() }
    }
}

enum SigningKeyPair {
    Ed25519(signature::Ed25519KeyPair),
    // TODO non-exhaustive enum https://github.com/rust-lang/rust/issues/44109
    #[doc(hidden)] __Nonexhaustive,
}

enum SigningKey<'a> {
    Ed25519(untrusted::Input<'a>),
    #[doc(hidden)] __Nonexhaustive,
}

enum IdentKeyPair {
    // TODO: This should not be ephemeral; is a permanent key
    // see https://github.com/briansmith/ring/issues/331
    Curve25519(agreement::EphemeralPrivateKey),
    #[doc(hidden)] __Nonexhaustive,
}

enum IdentKey<'a> {
    Curve25519(untrusted::Input<'a>),
    #[doc(hidden)] __Nonexhaustive,
}

enum OneTimeKeyPair {
    // TODO: This should not be ephemeral if these are to survive shutdown of the app
    // see https://github.com/briansmith/ring/issues/331
    Curve25519(agreement::EphemeralPrivateKey),
    #[doc(hidden)] __Nonexhaustive,
}

enum OneTimeKey<'a> {
    Curve25519(untrusted::Input<'a>),
    #[doc(hidden)] __Nonexhaustive,
}

const DEFAULT_NUM_ONE_TIME_KEY_PAIRS: u8 = 5;

pub struct LocalDevice {
    device_id: DeviceId,
    keypair: SigningKeyPair,
    ident_curve_pair: IdentKeyPair,
    one_time_key_pairs: HashMap<Vec<u8>, OneTimeKeyPair>,
}

impl<'a> LocalDevice {
    /// Initialize a new device
    ///
    /// To be used when creating a new device; use `LocalDevice::from_file` when reloading an old
    /// device.
    ///
    /// ```
    /// let my_dev = olm::olm::device::LocalDevice::init();
    /// ```
    pub fn init() -> Result<Self> {
        use rand::Rng;

        // TODO: Should the device_id be cryptographically random?
        let device_id = DeviceId::from(
            ::rand::thread_rng()
                .gen_ascii_chars()
                .take(10)
                .collect::<String>(),
        );

        // TODO share one rng in lib
        let rng = ring::rand::SystemRandom::new();

        // Generate a new signing key
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .chain_err(|| "Unable to generate signature key")?;
        // TODO Normally the application would store the PKCS#8 file persistently. Later it would
        // read the PKCS#8 file from persistent storage to use it.
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8_bytes))?;

        let ident_curve_pair = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let mut one_time_key_pairs = HashMap::new();

        for _ in 0..DEFAULT_NUM_ONE_TIME_KEY_PAIRS {
            let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
            let mut public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
            let public_key = &mut public_key[..private_key.public_key_len()];
            private_key.compute_public_key(public_key)?;

            one_time_key_pairs.insert(public_key.to_vec(), OneTimeKeyPair::Curve25519(private_key));
        }

        Ok(LocalDevice {
            device_id: device_id,
            keypair: SigningKeyPair::Ed25519(key_pair),
            ident_curve_pair: IdentKeyPair::Curve25519(ident_curve_pair),
            one_time_key_pairs: one_time_key_pairs,
        })
    }

    /// Load device config from file
    ///
    /// Needs forthcoming updates to ring; see https://github.com/briansmith/ring/issues/331
    pub fn from_file() -> Result<Self> {
        unimplemented!()
    }

    /// Save device config
    ///
    /// unimplemented
    pub fn to_file(&self) {
        unimplemented!()
    }
}

pub struct RemoteDevice<'a> {
    device_id: DeviceId,
    keypair: SigningKey<'a>,
    ident_curve_pair: IdentKey<'a>,
}

pub trait Device {
    /// Get device fingerprint
    fn fingerprint(&self);

    /// Get device ID
    fn get_device_id(&self) -> &DeviceId;

    fn ident_curve25519(&self);
}

impl Device for LocalDevice {
    /// Get device fingerprint
    fn fingerprint(&self) {
        unimplemented!()
    }

    /// Get device ID
    fn get_device_id(&self) -> &DeviceId {
        unimplemented!()
    }

    fn ident_curve25519(&self) {
        unimplemented!()
    }
}

impl<'a> Device for RemoteDevice<'a> {
    /// Get device fingerprint
    fn fingerprint(&self) {
        unimplemented!()
    }

    /// Get device ID
    fn get_device_id(&self) -> &DeviceId {
        unimplemented!()
    }

    fn ident_curve25519(&self) {
        unimplemented!()
    }
}
