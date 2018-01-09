use std::fmt;
use untrusted;
use util;
use errors::*;
use olm::{identity_key, one_time_key, ratchet, signing_key};
use olm::signing_key::SigningKey;

use ruma_identifiers::UserId;

#[derive(Debug, Clone)]
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
    /// let d = olm::device::DeviceId::from("DEVID");
    /// let s: String = d.to_string();
    /// ```
    fn from(s: S) -> DeviceId {
        DeviceId { id: s.into() }
    }
}

// TODO: Rewrite with std::convert
impl DeviceId {
    pub fn to_string(&self) -> String {
        self.id.clone()
    }
}

pub struct LocalDevice {
    user_id: UserId,
    device_id: DeviceId,
    signing_key_pair: signing_key::Ed25519Pair,
    ident_key_priv: identity_key::Curve25519Priv,
    one_time_key_pairs: one_time_key::Store,
    ratchets: ratchet::Store,
}

impl LocalDevice {
    pub fn user_id(&self) -> UserId {
        self.user_id.clone()
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id.clone()
    }
}

impl LocalDevice {
    /// Initialize a new device for given user
    ///
    /// To be used when creating a new device; use `LocalDevice::from_file` when reloading an old
    /// device.
    ///
    /// ```
    /// # #![feature(try_from)]
    /// use std::convert::TryFrom;
    ///
    /// extern crate olm;
    /// extern crate ruma_identifiers;
    /// use ruma_identifiers::UserId;
    ///
    /// fn main() {
    ///     let user_id = UserId::try_from("@example:matrix.org").unwrap();
    ///     let my_dev = olm::device::LocalDevice::init(user_id);
    /// }
    /// ```
    pub fn init(user_id: UserId) -> Result<Self> {
        use rand::Rng;

        // TODO: Should the device_id be cryptographically random?
        let device_id = DeviceId::from(
            ::rand::thread_rng()
                .gen_ascii_chars()
                .take(10)
                .collect::<String>(),
        );

        Ok(LocalDevice {
            user_id: user_id,
            device_id: device_id,
            signing_key_pair: signing_key::Ed25519Pair::generate()?,
            ident_key_priv: identity_key::Curve25519Priv::generate_unrandom()?,
            one_time_key_pairs: one_time_key::Store::generate()?,
            ratchets: ratchet::Store::new(),
        })
    }

    /// Get one-time public keys
    pub fn get_one_time_keys(&self) -> Vec<&one_time_key::Curve25519Pub> {
        self.one_time_key_pairs.get_keys()
    }

    /// Check if we have a one-time key

    /// # Examples
    /// ```
    /// # #![feature(try_from)]
    /// use std::convert::TryFrom;
    ///
    /// extern crate olm;
    /// extern crate ruma_identifiers;
    /// use ruma_identifiers::UserId;
    ///
    /// fn main() {
    ///     let user_id = UserId::try_from("@example:matrix.org").unwrap();
    ///     let my_dev = olm::device::LocalDevice::init(user_id).unwrap();
    ///     let keys = my_dev.get_one_time_keys();
    ///     assert!(my_dev.contains(keys[2]));
    /// }
    /// ```
    pub fn contains(&self, k: &one_time_key::Curve25519Pub) -> bool {
        self.one_time_key_pairs.contains_key(k)
    }
}

pub struct RemoteDevice {
    user_id: UserId,
    device_id: DeviceId,
    signing_key: signing_key::Ed25519Pub,
    ident_key: identity_key::Curve25519Pub,
}

pub trait Device {
    /// Get device fingerprint
    fn fingerprint(&self) -> untrusted::Input;

    /// Get device fingerprint in base 64
    ///
    /// # Examples
    /// ```
    /// # #![feature(try_from)]
    /// use std::convert::TryFrom;
    ///
    /// extern crate olm;
    /// use olm::device::Device;
    /// extern crate ruma_identifiers;
    /// use ruma_identifiers::UserId;
    ///
    /// fn main() {
    ///     let user_id = UserId::try_from("@example:matrix.org").unwrap();
    ///     let my_dev = olm::device::LocalDevice::init(user_id).unwrap();
    ///     my_dev.fingerprint_base64();
    /// }
    /// ```
    fn fingerprint_base64(&self) -> String;

    /// Get device ID
    ///
    /// # Examples
    // TODO use a fixed device and show that the ID is as expected
    /// ```
    /// # #![feature(try_from)]
    /// use std::convert::TryFrom;
    ///
    /// extern crate olm;
    /// use olm::device::Device;
    /// extern crate ruma_identifiers;
    /// use ruma_identifiers::UserId;
    ///
    /// fn main() {
    ///     let user_id = UserId::try_from("@example:matrix.org").unwrap();
    ///     let my_dev = olm::device::LocalDevice::init(user_id).unwrap();
    ///     my_dev.get_device_id();
    /// }
    /// ```
    fn get_device_id(&self) -> &DeviceId;

    fn get_ident_key(&self) -> &identity_key::Curve25519Pub;
}

impl Device for LocalDevice {
    /// Get device fingerprint
    fn fingerprint(&self) -> untrusted::Input {
        self.signing_key_pair.public_key()
    }

    fn fingerprint_base64(&self) -> String {
        util::bin_to_base64(self.fingerprint().as_slice_less_safe())
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
    fn fingerprint(&self) -> untrusted::Input {
        self.signing_key.public_key()
    }

    fn fingerprint_base64(&self) -> String {
        util::bin_to_base64(self.fingerprint().as_slice_less_safe())
    }
    /// Get device ID
    fn get_device_id(&self) -> &DeviceId {
        &self.device_id
    }

    fn get_ident_key(&self) -> &identity_key::Curve25519Pub {
        &self.ident_key
    }
}
