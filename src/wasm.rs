use crate::{core::Id, errors::WasmError};

pub trait Wasm {
    fn reset(&mut self) -> Result<(), WasmError>;
    fn objects(&mut self, f: impl FnMut(&Id)) -> Result<(), WasmError>;
    fn inputs(&mut self, f: impl FnMut(&Id)) -> Result<(), WasmError>;

    fn deploy(&mut self, code: &[u8], class_id: &Id) -> Result<Id, WasmError>;
    fn create(&mut self, class_id: &Id, object_id: &Id) -> Result<(), WasmError>;
    fn call(&mut self, object_id: &Id) -> Result<(), WasmError>;
    fn state<T>(&mut self, object_id: &Id, f: impl FnMut(&[u8]) -> T) -> Result<T, WasmError>;
    fn class(&mut self, object_id: &Id) -> Result<Id, WasmError>;
}

pub struct WasmImpl {}

impl Wasm for WasmImpl {
    fn reset(&mut self) -> Result<(), WasmError> {
        // TODO
        unimplemented!();
    }

    fn objects(&mut self, _f: impl FnMut(&Id)) -> Result<(), WasmError> {
        // TODO
        unimplemented!();
    }

    fn inputs(&mut self, _f: impl FnMut(&Id)) -> Result<(), WasmError> {
        // TODO
        unimplemented!();
    }

    fn deploy(&mut self, _code: &[u8], _class_id: &Id) -> Result<Id, WasmError> {
        // TODO
        unimplemented!();
    }

    fn create(&mut self, _class_id: &Id, _object_id: &Id) -> Result<(), WasmError> {
        // TODO
        unimplemented!();
    }

    fn call(&mut self, _object_id: &Id) -> Result<(), WasmError> {
        // TODO
        unimplemented!();
    }

    fn state<T>(&mut self, _object_id: &Id, _f: impl FnMut(&[u8]) -> T) -> Result<T, WasmError> {
        // TODO
        unimplemented!();
    }

    fn class(&mut self, _object_id: &Id) -> Result<Id, WasmError> {
        // TODO
        unimplemented!();
    }
}
