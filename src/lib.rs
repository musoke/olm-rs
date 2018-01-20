#![feature(try_from)]
#![recursion_limit = "1024"]
#[macro_use]
extern crate error_chain;

#[allow(unused_doc_comment)] // Should be fixed in next version on error_chain
mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{
        links {
            Olm(::olm::Error, ::olm::ErrorKind);
            Megolm(::megolm::Error, ::megolm::ErrorKind);
        }
    }
}

pub use errors::*;

#[cfg(test)]
extern crate env_logger;
#[macro_use]
extern crate log;

extern crate base64;
extern crate crypto;
extern crate rand;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate untrusted;

extern crate ruma_client_api;
extern crate ruma_identifiers;
extern crate ruma_signatures;

pub mod device;
pub mod olm;
pub mod megolm;
pub mod api;
mod util;

#[cfg(test)]
mod tests {}
