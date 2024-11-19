use crate::core::Id;
use std::collections::HashMap;

// TODO: Error?
pub trait ObjectProvider {
    fn object<T>(&self, id: &Id, callback: impl FnMut(Option<&[u8]>) -> T) -> T;
}

pub struct ObjectProviderImpl {
    objects: HashMap<Id, Vec<u8>>,
}

impl ObjectProviderImpl {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
        }
    }

    pub fn insert(&mut self, id: Id, data: Vec<u8>) {
        self.objects.insert(id, data);
    }
}

impl ObjectProvider for ObjectProviderImpl {
    fn object<T>(&self, id: &Id, mut callback: impl FnMut(Option<&[u8]>) -> T) -> T {
        callback(self.objects.get(id).map(|v| v.as_slice()))
    }
}
