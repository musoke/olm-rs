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
            Base64DecodeError
        }
    }
}

pub use self::errors::*;

pub mod signing_key;
pub mod identity_key;
pub mod one_time_key;
pub mod ratchet;
