use errors::*;
use device::{Device, LocalDevice};

use ruma_identifiers::UserId;
use ruma_client_api::unstable::keys::DeviceKeys;
use ruma_signatures::UserSignatures;

use std::collections::HashMap;

impl LocalDevice {
    /// Create a new device for the given user
    ///
    /// Named to match the corresponding function in the reference olm implementation.
    ///
    /// # Examples
    /// ```
    /// # #![feature(try_from)]
    /// use std::convert::TryFrom;
    ///
    /// extern crate olm;
    /// extern crate ruma_identifiers;
    /// use olm::device::LocalDevice;
    /// use ruma_identifiers::UserId;
    ///
    /// fn main() {
    ///     let _my_dev = LocalDevice::olm_create_account(
    ///         UserId::try_from("@user:example.com").unwrap()
    ///     );
    /// }
    /// ```
    pub fn olm_create_account(user_id: UserId) -> Result<Self> {
        let device = LocalDevice::init(user_id).chain_err(|| "Failed to create device")?;

        Ok(device)
    }

    /// Get object containing identity keys
    ///
    /// Unlike reference olm, this is immediately ready to be used in a request.
    ///
    /// Unimplemented: sign the object
    pub fn olm_acount_identity_keys(&self) -> DeviceKeys {
        let mut keys = HashMap::new();

        keys.insert(
            format!("{}:{}", "ed25519", self.device_id().to_string()).to_string(),
            self.fingerprint_base64(),
        );

        keys.insert(
            format!("{}:{}", "curve25519", self.device_id().to_string()).to_string(),
            self.fingerprint_base64(),
        );

        let device_keys = DeviceKeys {
            user_id: self.user_id(),
            device_id: self.device_id().to_string(),
            // TODO: other algorithms
            algorithms: vec!["m.olm.curve25519-aes-sha256".to_string()],
            keys: keys,
            signatures: UserSignatures::with_capacity(1),
            unsigned: None,
        };

        // TODO: sign object

        device_keys
    }

    /// Generate one-time keys
    ///
    /// Unlike reference olm, returns the new keys immediately.
    /// olm has the separate function `olm_account_one_time_keys` to actually retrieve the
    /// unpublished keys.
    pub fn olm_account_generate_one_time_keys(&self) -> HashMap<String, String> {
        unimplemented!()
    }
}
