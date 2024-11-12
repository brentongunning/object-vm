use crate::{core::Id, errors::WasmError};

pub trait Wasm {
    fn deploy(&mut self, code: &[u8]) -> Result<Id, WasmError>;
    fn create(&mut self, class_id: &Id, object_id: &Id) -> Result<(), WasmError>;
    fn call(&mut self, object_id: &Id) -> Result<(), WasmError>;
    fn state(&mut self, object_id: &Id) -> Result<(), WasmError>;
    fn class(&mut self, object_id: &Id) -> Result<Id, WasmError>;
}

pub struct WasmImpl {}

impl Wasm for WasmImpl {
    fn deploy(&mut self, _code: &[u8]) -> Result<Id, WasmError> {
        unimplemented!();
    }

    fn create(&mut self, _class_id: &Id, _object_id: &Id) -> Result<(), WasmError> {
        unimplemented!();
    }

    fn call(&mut self, _object_id: &Id) -> Result<(), WasmError> {
        unimplemented!();
    }

    fn state(&mut self, _object_id: &Id) -> Result<(), WasmError> {
        unimplemented!();
    }

    fn class(&mut self, _object_id: &Id) -> Result<Id, WasmError> {
        unimplemented!();
    }
}
