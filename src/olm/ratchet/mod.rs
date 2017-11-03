use ring;
use ring::agreement;
use ring::{hkdf, hmac};
use std::collections::HashMap;
use olm::errors::*;
use olm::{identity_key, one_time_key};
use olm::one_time_key::{OneTimeKey, OneTimeKeyPriv};
use olm::identity_key::{IdentityKey, IdentityKeyPriv};

use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};


pub struct Store {
    hashmap: HashMap<RatchetId, Ratchet>,
}

impl Store {
    pub fn new() -> Self {
        Self { hashmap: HashMap::new() }
    }

    pub fn import() -> Self {
        unimplemented!()
    }

    pub fn export() -> Self {
        unimplemented!()
    }
}

impl Store {
    fn insert(&mut self, r: Ratchet) {
        self.hashmap.insert(r.id(), r);
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct RatchetId {}

#[derive(Debug)]
struct Ratchet {
    id: RatchetId,
    algorithm: (),
    pre_key: bool,
    state: State,
}

#[derive(Debug)]
#[derive(Default)]
struct State {
    dh_self: Option<one_time_key::Curve25519Priv>,
    dh_remote: Option<one_time_key::Curve25519Pub>,
    root_key: [u8; 32],
    chain_key_sending: Option<[u8; 32]>,
    chain_key_receive: Option<[u8; 32]>,
    n_sending: usize,
    n_receive: usize,
    n_previous: usize,
    mk_skipped: HashMap<(one_time_key::Curve25519Pub, usize), [u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[derive(Debug, Clone)]
struct MessageHeader {
    pub dh_key: one_time_key::Curve25519Pub,
    pub n_previous: usize,
    pub n: usize,
}

impl Ratchet {
    pub fn init_sending(
        ident_alice: identity_key::Curve25519Priv,
        one_time_alice: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: &identity_key::Curve25519Pub,
        one_time_bob: one_time_key::Curve25519Pub,
    ) -> Result<Self> {

        let state = State::init_sending(ident_alice, one_time_alice, ident_bob, one_time_bob)
            .chain_err(|| "Failed to initialize ratchet for sending")?;

        Ok(Ratchet {
            id: RatchetId {},
            algorithm: (),
            pre_key: true,
            state: state,
        })
    }

    pub fn init_receiving(
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: identity_key::Curve25519Priv,
        one_time_bob: one_time_key::Curve25519Priv,
        ident_alice: &identity_key::Curve25519Pub,
        one_time_alice: one_time_key::Curve25519Pub,
        header: MessageHeader,
        ciphertext: &Vec<u8>,
    ) -> Result<Self> {

        let state =
            State::init_receiving(ident_bob, one_time_bob, ident_alice, one_time_alice, header)
                .chain_err(|| "Failed to initialize ratchet for receiving")?;

        // TODO: Check if decryptable and authentication is correct? If so, should discard the
        // one-time key in the calling function

        Ok(Ratchet {
            id: RatchetId {},
            algorithm: (),
            pre_key: false,
            state: state,
        })
    }

    pub fn encrypt(&mut self, plaintext: &Vec<u8>) -> Result<(MessageHeader, Vec<u8>)> {
        let (header, ciphertext) = self.state.state_encrypt(plaintext)?;

        Ok((header, ciphertext))
    }

    pub fn decrypt(&mut self, header: MessageHeader, ciphertext: &Vec<u8>) -> Result<Vec<u8>> {
        let plaintext = self.state.state_decrypt(header, ciphertext)?;

        Ok(plaintext)
    }
}

impl State {
    // TODO: what does Olm define?
    // The double ratchet docs say this should be identical across implementations.
    // https://signal.org/docs/specifications/doubleratchet/#implementation-fingerprinting
    const MAX_SKIP: usize = 1000;

    pub fn init_sending(
        ident_alice: identity_key::Curve25519Priv,
        one_time_alice: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: &identity_key::Curve25519Pub,
        one_time_bob: one_time_key::Curve25519Pub,
    ) -> Result<Self> {
        let mut state: State = Default::default();

        let dh_self_priv = one_time_key::Curve25519Priv::generate_unrandom()?;
        state.dh_self = Some(dh_self_priv);

        let shared_secret =
            State::x3dh_local(ident_alice, one_time_alice, ident_bob, one_time_bob)?;
        let (root, chain) = State::kdf_rk_init(shared_secret);

        state.root_key = root;
        state.chain_key_sending = Some(chain);

        Ok(state)
    }

    pub fn init_receiving(
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_bob: identity_key::Curve25519Priv,
        one_time_bob: one_time_key::Curve25519Priv,
        ident_alice: &identity_key::Curve25519Pub,
        one_time_alice: one_time_key::Curve25519Pub,
        header: MessageHeader,
    ) -> Result<Self> {
        let mut state: State = Default::default();

        let shared_secret =
            State::x3dh_remote(ident_bob, one_time_bob, ident_alice, one_time_alice)?;
        let (root, chain) = State::kdf_rk_init(shared_secret);

        state.root_key = root;
        state.chain_key_receive = Some(chain);

        // Set remote DH key
        state.dh_remote = Some(header.dh_key);

        // Create local DH key
        state.dh_self = Some(one_time_key::Curve25519Priv::generate_unrandom()?);

        // Ratchet to get sending chain
        let dh_out = state.ecdh()?;
        let (rk, cks) = State::kdf_rk(state.root_key, dh_out);
        state.root_key = rk;
        state.chain_key_sending = Some(cks);

        Ok(state)
    }

    fn x3dh_local(
        ident_local: identity_key::Curve25519Priv,
        one_time_local: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_remote: &identity_key::Curve25519Pub,
        one_time_remote: one_time_key::Curve25519Pub,
    ) -> Result<Vec<u8>> {
        // TODO: change once non-ephemeral keys are available

        let mut secret_1 = agreement::agree_ephemeral(
            ident_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_2 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            ident_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_3 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut s = Vec::new();
        s.append(&mut secret_1);
        s.append(&mut secret_2);
        s.append(&mut secret_3);

        Ok(s)
    }

    fn x3dh_remote(
        ident_local: identity_key::Curve25519Priv,
        one_time_local: one_time_key::Curve25519Priv,
        // TODO: ident_bob should not be consumed once it is non-ephemeral
        ident_remote: &identity_key::Curve25519Pub,
        one_time_remote: one_time_key::Curve25519Pub,
    ) -> Result<Vec<u8>> {
        // TODO: change once non-ephemeral keys are available

        let mut secret_1 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            ident_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_2 = agreement::agree_ephemeral(
            ident_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut secret_3 = agreement::agree_ephemeral(
            one_time_local.private_key(),
            &agreement::X25519,
            one_time_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "Agreement error")?;

        let mut s = Vec::new();
        s.append(&mut secret_1);
        s.append(&mut secret_2);
        s.append(&mut secret_3);

        Ok(s)
    }

    /// Derive the initial root key and chain key
    fn kdf_rk_init(shared_secret: Vec<u8>) -> ([u8; 32], [u8; 32]) {
        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let initial_salt: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, &[0]);

        let mut secret: [u8; 64] = [0; 64];
        hkdf::extract_and_expand(
            initial_salt,
            &shared_secret,
            "OLM_ROOT".as_bytes(),
            &mut secret,
        );

        let mut root: [u8; 32] = [0; 32];
        let mut chain: [u8; 32] = [0; 32];
        root.copy_from_slice(&secret[0..32]);
        chain.copy_from_slice(&secret[32..64]);

        (root, chain)
    }

    fn dh_ratchet(&mut self, header: &MessageHeader) -> Result<()> {
        self.n_previous = self.n_sending;
        self.n_sending = 0;
        self.n_receive = 0;
        // TODO: remove clone
        self.dh_remote = Some(header.dh_key.clone());

        // Ratchet to get new receiving chain
        let dh_out = self.ecdh()?;
        let (rk, ckr) = State::kdf_rk(self.root_key, dh_out);
        self.root_key = rk;
        self.chain_key_receive = Some(ckr);

        // Generate new DH key
        self.dh_self = Some(one_time_key::Curve25519Priv::generate_unrandom()?);

        // Ratchet to get new sending chain
        let dh_out = self.ecdh()?;
        let (rk, cks) = State::kdf_rk(self.root_key, dh_out);
        self.root_key = rk;
        self.chain_key_sending = Some(cks);

        Ok(())
    }

    /// Advance the root key and return the new root key and chain key
    fn kdf_rk(rk: [u8; 32], dh_out: Vec<u8>) -> ([u8; 32], [u8; 32]) {
        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let salt: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, &rk);

        let mut secret: [u8; 64] = [0; 64];
        hkdf::extract_and_expand(salt, &dh_out, b"OLM_RATCHET", &mut secret);

        let mut root: [u8; 32] = [0; 32];
        let mut chain: [u8; 32] = [0; 32];

        root.copy_from_slice(&secret[0..32]);
        chain.copy_from_slice(&secret[32..64]);

        (root, chain)
    }

    fn ecdh(&mut self) -> Result<Vec<u8>> {
        // Take the DH keys so that can use them
        let dh_self = self.dh_self.take().expect(
            "Should always have own private key",
        );
        let dh_remote = self.dh_remote.take().expect(
            "Should always have remote public key",
        );

        let secret = agreement::agree_ephemeral(
            dh_self.private_key(),
            &agreement::X25519,
            dh_remote.public_key(),
            ring::error::Unspecified,
            |s| Ok(s.to_vec()),
        ).chain_err(|| "ECDH agreement error")?;

        // Replace the original DH keys
        // FIXME There must be a better way to do this
        self.dh_self = Some(dh_self);
        self.dh_remote = Some(dh_remote);

        Ok(secret)
    }

    pub fn state_encrypt(&mut self, plaintext: &Vec<u8>) -> Result<(MessageHeader, Vec<u8>)> {
        let n_sending = self.n_sending;

        let (ck, mk) = State::kdf_ck(self.chain_key_sending.expect("Should have a sending chain"));
        self.chain_key_sending = Some(ck);
        self.n_sending += 1;

        let (aes_key, hmac_key, aes_iv) = State::derive_aead_keys(mk);

        let ciphertext = State::encrypt(aes_key, aes_iv, plaintext)?;


        let header = MessageHeader {
            dh_key: self.dh_self_public().unwrap(),
            n_previous: self.n_previous,
            n: n_sending,
        };

        // FIXME: do HMAC

        // FIXME: do message format

        Ok((header, ciphertext))
    }

    fn dh_self_public(&mut self) -> Option<one_time_key::Curve25519Pub> {
        // TODO: this is a hack?
        let private = self.dh_self.take().unwrap();
        let public = private.public_key();
        self.dh_self = Some(private);

        Some(public)
    }

    pub fn state_decrypt(
        &mut self,
        header: MessageHeader,
        ciphertext: &Vec<u8>,
    ) -> Result<Vec<u8>> {
        match self.try_skipped_message_keys(&header, &ciphertext)? {
            Some(plaintext) => {
                Ok(plaintext)
            }
            None => {
                match self.dh_remote {
                    Some(ref current_dh_key) if current_dh_key == &header.dh_key => {
                        // Current root key is correct, don't advance
                    }
                    None | Some(_) => {
                        self.skip_message_keys(header.n_previous)?;
                        self.dh_ratchet(&header)?;
                    }
                }

                self.skip_message_keys(header.n)?;

                let (ckr, mk) =
                    State::kdf_ck(self.chain_key_receive.expect("Should have a sending chain"));
                self.chain_key_receive = Some(ckr);
                self.n_receive += 1;

                State::decrypt_and_auth(mk, &ciphertext).chain_err(|| "Failed to decrypt message")
            }
        }
    }

    fn try_skipped_message_keys(
        &mut self,
        header: &MessageHeader,
        ciphertext: &Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        // TODO Note that this consumes the mk. I think this is the correct behaviour, but should
        // confirm.
        // TODO is there a way around cloning dh_key?
        if let Some(mk) = self.mk_skipped.remove(&(header.dh_key.clone(), header.n)) {
            Ok(Some(State::decrypt_and_auth(mk, ciphertext).chain_err(
                || "Failed to decrypt skipped message",
            )?))
        } else {
            Ok(None)
        }
    }

    fn skip_message_keys(&mut self, until: usize) -> Result<()> {
        if self.n_receive + State::MAX_SKIP < until {
            // Error::from("To many skipped messages")
            unimplemented!()
        } else if self.chain_key_receive.is_some() {
            while self.n_receive < until {
                let (ck, mk) = State::kdf_ck(self.chain_key_receive.unwrap());
                self.mk_skipped.insert(
                    (
                        // TODO remove this clone
                        self.dh_remote.clone().expect("dh_receive set before this"),
                        self.n_receive,
                    ),
                    mk,
                );
                self.chain_key_receive = Some(ck);
                self.n_receive += 1;
            }
            Ok(())
        } else {
            Ok(())
        }
    }


    fn encrypt(aes_key: [u8; 32], aes_iv: [u8; 16], plaintext: &Vec<u8>) -> Result<Vec<u8>> {

        use crypto;
        use crypto::aes;

        println!("aes_key: {:?}", aes_key);
        println!("aes_iv: {:?}", aes_iv);

        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            &aes_key,
            &aes_iv,
            crypto::blockmodes::PkcsPadding,
        );

        let mut ciphertext = Vec::<u8>::new();
        let mut read_buffer = crypto::buffer::RefReadBuffer::new(plaintext);
        let mut buffer = [0; 4096];
        let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

        loop {

            let result = encryptor
                .encrypt(&mut read_buffer, &mut write_buffer, true)
                .expect("Can encrypt to buffer");

            ciphertext.extend(
                write_buffer
                    .take_read_buffer()
                    .take_remaining()
                    .iter()
                    .map(|&i| i),
            );

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        Ok(ciphertext)
    }

    fn decrypt_and_auth(mk: [u8; 32], ciphertext: &Vec<u8>) -> Result<Vec<u8>> {

        let (aes_key, hmac_key, aes_iv) = State::derive_aead_keys(mk);

        // FIXME: HMAC auth

        let plaintext = State::decrypt(aes_key, aes_iv, ciphertext)?;

        Ok(plaintext)
    }

    fn decrypt(aes_key: [u8; 32], aes_iv: [u8; 16], ciphertext: &Vec<u8>) -> Result<Vec<u8>> {

        println!("aes_key: {:?}", aes_key);
        println!("aes_iv: {:?}", aes_iv);

        use crypto;
        use crypto::aes;

        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            &aes_key,
            &aes_iv,
            crypto::blockmodes::PkcsPadding,
        );

        let mut plaintext = Vec::<u8>::new();
        let mut read_buffer = crypto::buffer::RefReadBuffer::new(ciphertext);
        let mut buffer = [0; 4096];
        let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

        loop {

            let result = decryptor
                .decrypt(&mut read_buffer, &mut write_buffer, true)
                .expect("Can decrypt to buffer");

            plaintext.extend(
                write_buffer
                    .take_read_buffer()
                    .take_remaining()
                    .iter()
                    .map(|&i| i),
            );

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        Ok(plaintext)
    }

    /// Derive AES-256 CBC and HMAC-SHA-256 keys and IV from a message key
    fn derive_aead_keys(mk: [u8; 32]) -> ([u8; 32], [u8; 32], [u8; 16]) {
        // TODO: HKDF_HASH should probably be a static
        let hkdf_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let salt: &ring::hmac::SigningKey = &hmac::SigningKey::new(hkdf_hash, &[0]);

        let mut secret: [u8; 80] = [0; 80];
        hkdf::extract_and_expand(salt, &mk, b"OLM_KEYS", &mut secret);

        let mut aes_key: [u8; 32] = [0; 32];
        let mut hmac_key: [u8; 32] = [0; 32];
        let mut aes_iv: [u8; 16] = [0; 16];

        aes_key.copy_from_slice(&secret[0..32]);
        hmac_key.copy_from_slice(&secret[32..64]);
        aes_iv.copy_from_slice(&secret[64..80]);

        (aes_key, hmac_key, aes_iv)
    }

    /// Derive message key from chain key
    fn kdf_mk(ck: &[u8; 32]) -> [u8; 32] {
        // TODO: HMAC_HASH should probably be a static
        let hmac_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let c: &ring::hmac::SigningKey = &hmac::SigningKey::new(hmac_hash, ck);

        // TODO: is this correct?
        let data: [u8; 1] = [0x01];

        let sig = hmac::sign(c, &data);

        let mut mk = [0; 32];
        mk.copy_from_slice(sig.as_ref());

        mk
    }

    /// Derive next chain key and current message key from current chain key
    ///
    /// This consumes C_{i,j} and returns C{i,j+1}, M_{i,j}
    ///
    /// Note that this consumes the input chain key whereas `kdf_mk` does not.
    fn kdf_ck(ck: [u8; 32]) -> ([u8; 32], [u8; 32]) {

        let mk = State::kdf_mk(&ck);

        // TODO: HMAC_HASH should probably be a static
        let hmac_hash: &ring::digest::Algorithm = &ring::digest::SHA256;
        let c: &ring::hmac::SigningKey = &hmac::SigningKey::new(hmac_hash, &ck);

        // TODO: is this correct?
        let data: [u8; 1] = [0x02];

        let sig = hmac::sign(c, &data);

        let mut ck = [0; 32];
        ck.copy_from_slice(sig.as_ref());

        (ck, mk)
    }
}

impl Ratchet {
    pub fn id(&self) -> RatchetId {
        self.id.clone()
    }
}

#[cfg(test)]
mod test {

    use olm::{identity_key, one_time_key};
    use olm::identity_key::{IdentityKey, IdentityKeyPriv};
    use olm::one_time_key::{OneTimeKey, OneTimeKeyPriv};
    use olm::ratchet::Ratchet;

    fn generate_keys()
        -> ((identity_key::Curve25519Priv,
             one_time_key::Curve25519Priv,
             identity_key::Curve25519Pub,
             one_time_key::Curve25519Pub),
            (identity_key::Curve25519Priv,
             one_time_key::Curve25519Priv,
             identity_key::Curve25519Pub,
             one_time_key::Curve25519Pub))
    {

        let alice_ident_priv = identity_key::Curve25519Priv::generate_unrandom().unwrap();
        let alice_ident_pub = alice_ident_priv.public_key();
        let bob_ident_priv = identity_key::Curve25519Priv::generate_unrandom().unwrap();
        let bob_ident_pub = bob_ident_priv.public_key();

        let alice_one_time_priv = one_time_key::Curve25519Priv::generate_unrandom().unwrap();
        let alice_one_time_pub = alice_one_time_priv.public_key();
        let bob_one_time_priv = one_time_key::Curve25519Priv::generate_unrandom().unwrap();
        let bob_one_time_pub = bob_one_time_priv.public_key();

        (
            (
                alice_ident_priv,
                alice_one_time_priv,
                bob_ident_pub,
                bob_one_time_pub,
            ),
            (
                bob_ident_priv,
                bob_one_time_priv,
                alice_ident_pub,
                alice_one_time_pub,
            ),
        )
    }

    // Check that ratchet states are consistent when advancing chain key
    #[test]
    fn simple_encrypt_decrypt() {

        let (keys_alice, keys_bob) = generate_keys();

        let mut ratchet_alice =
            Ratchet::init_sending(keys_alice.0, keys_alice.1, &keys_alice.2, keys_alice.3)
                .expect("Can generate Alice's ratchet");

        let plain_alice = vec![0, 1, 2];

        let (header, ciphertext) = ratchet_alice.encrypt(&plain_alice).expect(
            "Can encrypt the message",
        );

        let mut ratchet_bob = Ratchet::init_receiving(
            keys_bob.0,
            keys_bob.1,
            &keys_bob.2,
            keys_bob.3,
            header.clone(),
            &ciphertext,
        ).expect("Can generate Bob's ratchet");

        // Root key shouldn't have changed
        assert_ne!(ratchet_alice.state.root_key, ratchet_bob.state.root_key);
        // Chain keys should be different until bob decrypts
        assert_ne!(
            ratchet_alice.state.chain_key_sending,
            ratchet_bob.state.chain_key_receive
        );
        assert_ne!(ciphertext.len(), 0);

        println!("ciphertext bytes: {:?}", ciphertext);
        println!("ciphertext length: {:?}", ciphertext.len());

        let plain_bob = ratchet_bob.decrypt(header, &ciphertext).expect(
            "Can decrypt the message",
        );

        // Alice's public DH key should match that of Bob
        assert_eq!(
            ratchet_alice.state.dh_self.unwrap().public_key(),
            ratchet_bob.state.dh_remote.unwrap()
        );

        // Bob's root key should have advanced
        assert_ne!(ratchet_alice.state.root_key, ratchet_bob.state.root_key);

        // Should get matching plaintext
        assert_eq!(plain_alice, plain_bob);

        // Chain keys should be the same now
        assert_eq!(
            ratchet_alice.state.chain_key_sending,
            ratchet_bob.state.chain_key_receive
        );

    }

    // Check decrypting multiple in order messages
    #[test]
    fn encrypt_decrypt_3() {

        let (keys_alice, keys_bob) = generate_keys();

        let mut ratchet_alice =
            Ratchet::init_sending(keys_alice.0, keys_alice.1, &keys_alice.2, keys_alice.3)
                .expect("Can generate Alice's ratchet");

        let plain_alice_1 = vec![0, 1, 2];
        let (header_1, ciphertext_1) = ratchet_alice.encrypt(&plain_alice_1).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let plain_alice_2 = vec![0, 1, 2, 3];
        let (header_2, ciphertext_2) = ratchet_alice.encrypt(&plain_alice_2).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let plain_alice_3 = vec![0, 1, 2];
        let (header_3, ciphertext_3) = ratchet_alice.encrypt(&plain_alice_1).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let mut ratchet_bob = Ratchet::init_receiving(
            keys_bob.0,
            keys_bob.1,
            &keys_bob.2,
            keys_bob.3,
            header_1.clone(),
            &ciphertext_1,
        ).expect("Can generate Bob's ratchet");

        // Decrypt 1st message
        let plain_bob_1 = ratchet_bob.decrypt(header_1, &ciphertext_1).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_1, plain_bob_1);

        // Decrypt 2nd message
        let plain_bob_2 = ratchet_bob.decrypt(header_2, &ciphertext_2).expect(
            "Can decrypt message",
        );
        assert_eq!(plain_alice_2, plain_bob_2);

        // Decrypt 3rd message
        let plain_bob_3 = ratchet_bob.decrypt(header_3, &ciphertext_3).expect(
            "Can decrypt message",
        );
        assert_eq!(plain_alice_3, plain_bob_3);

    }

    // Check decrypting multiple out of order messages
    #[test]
    fn out_of_order_1_3_2() {

        let (keys_alice, keys_bob) = generate_keys();

        let mut ratchet_alice =
            Ratchet::init_sending(keys_alice.0, keys_alice.1, &keys_alice.2, keys_alice.3)
                .expect("Can generate Alice's ratchet");

        let plain_alice_1 = vec![0, 1, 2];
        let (header_1, ciphertext_1) = ratchet_alice.encrypt(&plain_alice_1).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let plain_alice_2 = vec![0, 1, 2, 3];
        let (header_2, ciphertext_2) = ratchet_alice.encrypt(&plain_alice_2).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let plain_alice_3 = vec![0, 1, 2, 3, 4];
        let (header_3, ciphertext_3) = ratchet_alice.encrypt(&plain_alice_3).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let mut ratchet_bob = Ratchet::init_receiving(
            keys_bob.0,
            keys_bob.1,
            &keys_bob.2,
            keys_bob.3,
            header_1.clone(),
            &ciphertext_1,
        ).expect("Can generate Bob's ratchet");

        // Decrypt 1st message
        let plain_bob_1 = ratchet_bob.decrypt(header_1, &ciphertext_1).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_1, plain_bob_1);

        // Decrypt 3rd message
        let plain_bob_3 = ratchet_bob.decrypt(header_3, &ciphertext_3).expect(
            "Can decrypt message",
        );
        assert_eq!(plain_alice_3, plain_bob_3);

        // Decrypt 2nd message
        let plain_bob_2 = ratchet_bob.decrypt(header_2, &ciphertext_2).expect(
            "Can decrypt message",
        );
        assert_eq!(plain_alice_2, plain_bob_2);

    }

    // Check decrypting multiple out of order messages
    #[test]
    fn out_of_order_3_2_1() {

        let (keys_alice, keys_bob) = generate_keys();

        let mut ratchet_alice =
            Ratchet::init_sending(keys_alice.0, keys_alice.1, &keys_alice.2, keys_alice.3)
                .expect("Can generate Alice's ratchet");

        let plain_alice_1 = vec![0, 1, 2];
        let (header_1, ciphertext_1) = ratchet_alice.encrypt(&plain_alice_1).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let plain_alice_2 = vec![0, 1, 2, 3];
        let (header_2, ciphertext_2) = ratchet_alice.encrypt(&plain_alice_2).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let plain_alice_3 = vec![0, 1, 2, 3, 4];
        let (header_3, ciphertext_3) = ratchet_alice.encrypt(&plain_alice_3).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let mut ratchet_bob = Ratchet::init_receiving(
            keys_bob.0,
            keys_bob.1,
            &keys_bob.2,
            keys_bob.3,
            header_3.clone(),
            &ciphertext_3,
        ).expect("Can generate Bob's ratchet");

        // Decrypt 3rd message first
        let plain_bob_3 = ratchet_bob.decrypt(header_3, &ciphertext_3).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_3, plain_bob_3);

        // Decrypt 2nd message
        let plain_bob_2 = ratchet_bob.decrypt(header_2, &ciphertext_2).expect(
            "Can decrypt message",
        );
        assert_eq!(plain_alice_2, plain_bob_2);

        // Decrypt 1st message
        let plain_bob_1 = ratchet_bob.decrypt(header_1, &ciphertext_1).expect(
            "Can decrypt message",
        );
        assert_eq!(plain_alice_1, plain_bob_1);

    }

    // Replying to messages
    #[test]
    fn reply() {

        let (keys_alice, keys_bob) = generate_keys();

        let mut ratchet_alice =
            Ratchet::init_sending(keys_alice.0, keys_alice.1, &keys_alice.2, keys_alice.3)
                .expect("Can generate Alice's ratchet");

        let plain_alice_1 = vec![0, 1, 2];
        let (header_1, ciphertext_1) = ratchet_alice.encrypt(&plain_alice_1).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let mut ratchet_bob = Ratchet::init_receiving(
            keys_bob.0,
            keys_bob.1,
            &keys_bob.2,
            keys_bob.3,
            header_1.clone(),
            &ciphertext_1,
        ).expect("Can generate Bob's ratchet");

        // Decrypt 1st message
        let plain_bob_1 = ratchet_bob.decrypt(header_1, &ciphertext_1).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_1, plain_bob_1);

        let plain_bob_2 = vec![2, 1, 0];
        let (header_2, ciphertext_2) = ratchet_bob.encrypt(&plain_bob_2).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_2.len(), 0);

        // Decrypt reply
        let plain_alice_2 = ratchet_alice.decrypt(header_2, &ciphertext_2).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_2, plain_bob_2);

    }

    // Replying to messages
    #[test]
    fn reply_reply() {

        let (keys_alice, keys_bob) = generate_keys();

        let mut ratchet_alice =
            Ratchet::init_sending(keys_alice.0, keys_alice.1, &keys_alice.2, keys_alice.3)
                .expect("Can generate Alice's ratchet");

        // First message
        let plain_alice_1 = vec![0];
        let (header_1, ciphertext_1) = ratchet_alice.encrypt(&plain_alice_1).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_1.len(), 0);

        let mut ratchet_bob = Ratchet::init_receiving(
            keys_bob.0,
            keys_bob.1,
            &keys_bob.2,
            keys_bob.3,
            header_1.clone(),
            &ciphertext_1,
        ).expect("Can generate Bob's ratchet");
        let plain_bob_1 = ratchet_bob.decrypt(header_1, &ciphertext_1).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_1, plain_bob_1);

        // Reply
        let plain_bob_2 = vec![1];
        let (header_2, ciphertext_2) = ratchet_bob.encrypt(&plain_bob_2).expect(
            "Can encrypt the message",
        );
        assert_ne!(ciphertext_2.len(), 0);
        let plain_alice_2 = ratchet_alice.decrypt(header_2, &ciphertext_2).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_2, plain_bob_2);

        // Reply to reply
        println!("Encrypt message #3");
        let plain_alice_3 = vec![3];
        let (header_3, ciphertext_3) = ratchet_alice.encrypt(&plain_alice_3).expect(
            "Can encrypt the message",
        );
        println!("Decrypt message #3, header: {:?}", header_3);
        let plain_bob_3 = ratchet_bob.decrypt(header_3, &ciphertext_3).expect(
            "Can decrypt the first message",
        );
        assert_eq!(plain_alice_3, plain_bob_3);

    }

}
