use std::fmt;
use ring;
use ring::agreement;
use untrusted;
use std::collections::HashMap;
use olm::errors::*;
use util;
use olm::signing_key;

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

enum IdentKeyPair {
    // TODO: This should not be ephemeral; is a permanent key
    // see https://github.com/briansmith/ring/issues/331
    Curve25519(agreement::EphemeralPrivateKey),
    #[doc(hidden)] __Nonexhaustive,
}

pub enum IdentKey<'a> {
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

const DEFAULT_NUM_ONE_TIME_KEY_PAIRS: usize = 5;

pub struct LocalDevice {
    device_id: DeviceId,
    signing_key_pair: signing_key::Ed25519Pair,
    ident_key_pair: IdentKeyPair,
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

        let rng = ring::rand::SystemRandom::new();

        // Generate a new identity key
        let ident_key_pair = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let mut ident_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let ident_key = &mut ident_key[..ident_key_pair.public_key_len()];
        ident_key_pair.compute_public_key(ident_key)?;

        // Generate one time keys
        let mut one_time_key_pairs = HashMap::with_capacity(DEFAULT_NUM_ONE_TIME_KEY_PAIRS);

        for _ in 0..DEFAULT_NUM_ONE_TIME_KEY_PAIRS {
            let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
            let mut public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
            let public_key = &mut public_key[..private_key.public_key_len()];
            private_key.compute_public_key(public_key)?;

            one_time_key_pairs.insert(public_key.to_vec(), OneTimeKeyPair::Curve25519(private_key));
        }

        Ok(LocalDevice {
            device_id: device_id,
            signing_key_pair: signing_key::Ed25519Pair::generate()?,
            ident_key_pair: IdentKeyPair::Curve25519(ident_key_pair),
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
    pub fn to_file(&self) -> Result<()> {
        unimplemented!()
    }

    /// Get one-time public keys
    pub fn get_one_time_keys(&self) -> Vec<&Vec<u8>> {
        let mut keys = Vec::new();
        for k in self.one_time_key_pairs.keys() {
            keys.push(k)
        }
        keys
    }

    /// Check if we have a one-time key
    ///
    /// # Examples
    /// ```
    /// let my_dev = olm::olm::device::LocalDevice::init().unwrap();
    /// let keys = my_dev.get_one_time_keys();
    /// assert!(my_dev.check_one_time_key(keys[2]));
    /// ```
    pub fn check_one_time_key(&self, k: &Vec<u8>) -> bool {
        self.one_time_key_pairs.contains_key(k)
    }
}

pub struct RemoteDevice<'a> {
    device_id: DeviceId,
    signing_key: signing_key::Ed25519Pub,
    ident_key: IdentKey<'a>,
}

pub trait Device {
    /// Get device fingerprint
    fn fingerprint(&self) -> Vec<u8>;

    /// Get device fingerprint in base 64
    ///
    /// # Examples
    /// ```
    /// use olm::olm::device::Device;
    /// let d = olm::olm::device::LocalDevice::init().unwrap();
    /// d.fingerprint_base64();
    /// ```
    fn fingerprint_base64(&self) -> String;

    /// Get device ID
    ///
    /// # Examples
    // TODO use a fixed device and show that the ID is as expected
    /// ```
    /// use olm::olm::device::Device;
    /// let d = olm::olm::device::LocalDevice::init().unwrap();
    /// d.get_device_id();
    /// ```
    fn get_device_id(&self) -> &DeviceId;

    fn get_ident_key(&self) -> &IdentKey;
}

impl Device for LocalDevice {
    /// Get device fingerprint
    fn fingerprint(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn fingerprint_base64(&self) -> String {
        unimplemented!()
    }

    fn get_device_id(&self) -> &DeviceId {
        &self.device_id
    }

    fn get_ident_key(&self) -> &IdentKey {
        unimplemented!();
    }
}

impl<'a> Device for RemoteDevice<'a> {
    /// Get device fingerprint
    fn fingerprint(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn fingerprint_base64(&self) -> String {
        unimplemented!()
    }
    /// Get device ID
    fn get_device_id(&self) -> &DeviceId {
        &self.device_id
    }

    fn get_ident_key(&self) -> &IdentKey {
        &self.ident_key
    }
}
