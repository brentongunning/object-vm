use crate::{core::Id, errors::WasmError, misc::InputProvider};

pub trait Wasm {
    fn reset(&mut self) -> Result<(), WasmError>;
    fn objects(&mut self, f: impl FnMut(&Id)) -> Result<(), WasmError>;
    fn inputs(&mut self, f: impl FnMut(&Id)) -> Result<(), WasmError>;

    fn deploy(&mut self, code: &[u8], class_id: &Id) -> Result<(), WasmError>;
    fn create(&mut self, class_id: &Id, object_id: &Id) -> Result<(), WasmError>;
    fn call(&mut self, object_id: &Id) -> Result<(), WasmError>;
    fn state(&mut self, object_id: &Id) -> Result<&[u8], WasmError>;
    fn class(&mut self, object_id: &Id) -> Result<&Id, WasmError>;
}

pub struct WasmImpl<I: InputProvider> {
    _input_provider: I,
}

impl<I: InputProvider> WasmImpl<I> {
    pub fn new(input_provider: I) -> Self {
        Self {
            _input_provider: input_provider,
        }
    }
}

impl<I: InputProvider> Wasm for WasmImpl<I> {
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

    fn deploy(&mut self, _code: &[u8], _class_id: &Id) -> Result<(), WasmError> {
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

    fn state(&mut self, _object_id: &Id) -> Result<&[u8], WasmError> {
        // TODO
        unimplemented!();
    }

    fn class(&mut self, _object_id: &Id) -> Result<&Id, WasmError> {
        // TODO
        unimplemented!();
    }
}
