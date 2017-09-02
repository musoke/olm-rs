//! An API for Olm
//!

/// Module with errors handled by error_chain
#[allow(unused_doc_comment)] // Should be fixed in next version on error_chain
mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{
        links {}
        foreign_links {
            RingUnspecified(::ring::error::Unspecified);
        }
    }
}

pub use self::errors::*;

pub mod device;
