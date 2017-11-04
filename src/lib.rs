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

#[macro_use]
extern crate log;
#[cfg(test)]
extern crate env_logger;

extern crate base64;
extern crate rand;
extern crate ring;
extern crate crypto;
extern crate untrusted;
extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate ruma_identifiers;

pub mod device;
pub mod olm;
pub mod megolm;
mod util;


#[cfg(test)]
mod tests {}
