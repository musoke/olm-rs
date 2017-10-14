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

extern crate base64;
extern crate rand;
extern crate ring;
extern crate untrusted;


pub mod device;
pub mod olm;
pub mod megolm;
mod util;


#[cfg(test)]
mod tests {}
