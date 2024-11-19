use crate::core::Id;
use std::collections::HashMap;

// TODO: Error?
pub trait InputProvider {
    fn input<T>(&self, id: &Id, callback: impl FnMut(Option<&[u8]>) -> T) -> T;
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
    fn input<T>(&self, id: &Id, mut callback: impl FnMut(Option<&[u8]>) -> T) -> T {
        callback(self.inputs.get(id).map(|v| v.as_slice()))
    }
}
