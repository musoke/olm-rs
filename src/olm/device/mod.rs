use std::fmt;
use olm::errors::*;
use olm::{identity_key, one_time_key, signing_key};

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

pub struct LocalDevice {
    device_id: DeviceId,
    signing_key_pair: signing_key::Ed25519Pair,
    ident_key_priv: identity_key::Curve25519Priv,
    one_time_key_pairs: one_time_key::Store,
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

        Ok(LocalDevice {
            device_id: device_id,
            signing_key_pair: signing_key::Ed25519Pair::generate()?,
            ident_key_priv: identity_key::Curve25519Priv::generate()?,
            one_time_key_pairs: one_time_key::Store::generate()?,
        })
    }

    /// Load device config from file
    ///
    /// unimplemented
    ///
    /// Needs forthcoming updates to ring; see https://github.com/briansmith/ring/issues/331
    pub fn from_file() -> Result<Self> {
        unimplemented!()
    }

    /// Save device config
    ///
    /// unimplemented
    ///
    /// Needs forthcoming updates to ring; see https://github.com/briansmith/ring/issues/331
    pub fn to_file(&self) -> Result<()> {
        unimplemented!()
    }

    /// Get one-time public keys
    pub fn get_one_time_keys(&self) -> Vec<&one_time_key::Curve25519Pub> {
        self.one_time_key_pairs.get_keys()
    }

    /// Check if we have a one-time key

    /// # Examples
    /// ```
    /// let my_dev = olm::olm::device::LocalDevice::init().unwrap();
    /// let keys = my_dev.get_one_time_keys();
    /// assert!(my_dev.contains(keys[2]));
    /// ```
    pub fn contains(&self, k: &one_time_key::Curve25519Pub) -> bool {
        self.one_time_key_pairs.contains_key(k)
    }
}

pub struct RemoteDevice {
    device_id: DeviceId,
    signing_key: signing_key::Ed25519Pub,
    ident_key: identity_key::Curve25519Pub,
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
    // /// d.fingerprint_base64();
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

    fn get_ident_key(&self) -> &identity_key::Curve25519Pub;
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

    fn get_ident_key(&self) -> &identity_key::Curve25519Pub {
        unimplemented!();
    }
}

impl Device for RemoteDevice {
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

    fn get_ident_key(&self) -> &identity_key::Curve25519Pub {
        &self.ident_key
    }
}
