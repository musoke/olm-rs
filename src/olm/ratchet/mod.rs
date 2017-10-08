use ring;
use std::collections::HashMap;

pub struct Store {
    hashmap: HashMap<RatchetId, Ratchet>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            hashmap: HashMap::new(),
        }
    }

    pub fn import() -> Self {
        unimplemented!()
    }

    pub fn export() -> Self {
        unimplemented!()
    }
}


#[derive(Debug, PartialEq, Eq, Hash)]
struct RatchetId {}

#[derive(Debug)]
struct Ratchet {
    id: RatchetId,
    graph: (),
}

impl Ratchet {
    pub fn init() -> Self {
        Ratchet {
            id: RatchetId {},
            graph: (),
        }
    }

    pub fn import() -> Self {
        unimplemented!()
    }

    pub fn export() -> Self {
        unimplemented!()
    }
}

impl Ratchet {
    pub fn advance_root(&mut self) {}
    pub fn advance_message(&mut self) {}
}
