//! An API for Olm
//!

/// Module with errors handled by `error_chain`
#[allow(unused_doc_comment)] // Should be fixed in next version on error_chain
mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{
        links {}
        foreign_links {
            RingUnspecified(::ring::error::Unspecified);
        }
        errors {
            Base64DecodeError {
                description("An error occurred during base64 decoding")
                display("Unable to decode")
            }

            EncryptionError(kind: ::crypto::symmetriccipher::SymmetricCipherError) {
                description("An error occurred during message encryption")
                display("Unable to encrypt")
            }

            DecryptionError(kind: ::crypto::symmetriccipher::SymmetricCipherError) {
                description("An error occurred during message decryption")
                display("Unable to decrypt")
            }

            SkippedMessageOverflow {
                description("Too many skipped message keys")
            }
        }
    }
}

pub use self::errors::*;

pub mod signing_key;
pub mod identity_key;
pub mod one_time_key;
pub mod ratchet;
