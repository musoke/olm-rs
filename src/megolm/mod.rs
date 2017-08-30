mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{
        links {}
    }
}

pub use self::errors::*;
