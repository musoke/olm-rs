#![feature(try_from)]

#[macro_use]
extern crate failure;

extern crate core;

#[cfg(test)]
extern crate env_logger;
#[macro_use]
extern crate log;

extern crate base64;
extern crate crypto;
extern crate rand;
extern crate ring;
extern crate untrusted;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

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
