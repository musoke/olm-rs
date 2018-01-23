//! An API for Olm
//!

// #[derive(Debug, Fail)]
// enum OlmError {
//     #[fail(display = "invalid base64: {}", string)] Base64DecodeError { string: String },
//     #[fail(display = "unable to encrypt")] EncryptionError,
//     #[fail(display = "unable to decrypt")] DecryptionError,
//     #[fail(display = "skipped message overflow")] SkippedMessageOverflow,
// }

pub mod ratchet;
