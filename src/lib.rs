#![recursion_limit = "1024"]
#[macro_use]
extern crate error_chain;

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


mod olm;
mod megolm;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
