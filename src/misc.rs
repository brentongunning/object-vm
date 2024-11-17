use crate::core::Id;
use std::collections::HashMap;

pub trait InputProvider {
    fn input(&self, id: &Id) -> Option<&[u8]>;
}

pub struct InputProviderImpl {
    inputs: HashMap<Id, Vec<u8>>,
}

impl InputProviderImpl {
    pub fn new() -> Self {
        Self {
            inputs: HashMap::new(),
        }
    }

    pub fn insert(&mut self, id: Id, data: Vec<u8>) {
        self.inputs.insert(id, data);
    }
}

impl InputProvider for InputProviderImpl {
    fn input(&self, id: &Id) -> Option<&[u8]> {
        self.inputs.get(id).map(|v| v.as_slice())
    }
}
