use crate::{
    core::Id,
    errors::{VmError, WasmError},
    misc::InputProvider,
};
use std::{collections::HashSet, ptr::NonNull, sync::Arc};
use wasmer::{
    sys::{BaseTunables, EngineBuilder, Features},
    vm::{
        MemoryStyle, TableStyle, VMConfig, VMMemory, VMMemoryDefinition, VMTable, VMTableDefinition,
    },
    CompilerConfig, MemoryError, MemoryType, Module, Singlepass, Store, TableType, Tunables, Type,
};
use wasmer_middlewares::Metering;

// Because of how wasmer is implemented [1], the wasm stack gets shared across instances
// and cannot be configured per-module. It's also specific to this wasm implementation.
// Consensus will dictate the actual max stack size, so we set it big enough to be reasonable,
// avoid infinite recursion, and process historical blocks.
// [1] https://github.com/wasmerio/wasmer/blob/d3f02cb3daa3c214a230c672cb7309fde0646db9/lib/vm/src/trap/traphandlers.rs#L689
const WASM_STACK_SIZE: usize = 1024 * 1024;

// TODO: static call?
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
    _store: Store,
}

impl<I: InputProvider> WasmImpl<I> {
    pub fn new(input_provider: I) -> Self {
        Self {
            _input_provider: input_provider,
            _store: create_store(),
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

fn create_store() -> Store {
    let metering = Arc::new(Metering::new(i64::MAX as u64, |_op| 1));

    let mut singlepass = Singlepass::new();
    singlepass.push_middleware(metering);
    singlepass.canonicalize_nans(true);

    let mut engine = EngineBuilder::new(singlepass)
        .set_features(Some(features()))
        .engine();

    let base = BaseTunables::for_target(engine.target());
    let wasm_stack_size = Some(WASM_STACK_SIZE);
    let vmconfig = VMConfig { wasm_stack_size };
    let tunables = CustomTunables { vmconfig, base };
    engine.set_tunables(tunables);

    Store::new(engine)
}

fn features() -> Features {
    Features {
        bulk_memory: true,
        exceptions: false,
        extended_const: false,
        memory64: false,
        module_linking: false,
        multi_memory: false,
        multi_value: false, // https://github.com/wasmerio/wasmer/issues/3940
        reference_types: false,
        relaxed_simd: false,
        simd: false,
        tail_call: false,
        threads: false,
    }
}

struct CustomTunables<B: Tunables> {
    vmconfig: VMConfig,
    base: B,
}

impl<B: Tunables> Tunables for CustomTunables<B> {
    fn memory_style(&self, memory: &MemoryType) -> MemoryStyle {
        self.base.memory_style(memory)
    }

    fn table_style(&self, table: &TableType) -> TableStyle {
        self.base.table_style(table)
    }

    fn create_host_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
    ) -> Result<VMMemory, MemoryError> {
        self.base.create_host_memory(ty, style)
    }

    unsafe fn create_vm_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
        vm_definition_location: NonNull<VMMemoryDefinition>,
    ) -> Result<VMMemory, MemoryError> {
        self.base
            .create_vm_memory(ty, style, vm_definition_location)
    }

    fn create_host_table(&self, ty: &TableType, style: &TableStyle) -> Result<VMTable, String> {
        self.base.create_host_table(ty, style)
    }

    unsafe fn create_vm_table(
        &self,
        ty: &TableType,
        style: &TableStyle,
        vm_definition_location: NonNull<VMTableDefinition>,
    ) -> Result<VMTable, String> {
        self.base.create_vm_table(ty, style, vm_definition_location)
    }

    fn vmconfig(&self) -> &VMConfig {
        &self.vmconfig
    }
}

pub fn check_wasm(bytecode: &[u8], max_memory_pages: usize) -> Result<(), VmError> {
    let singlepass = Singlepass::new();
    let engine = EngineBuilder::new(singlepass)
        .set_features(Some(features()))
        .engine();
    let store = Store::new(&engine);
    let module_without_metering = Module::new(&store, bytecode)?;

    if module_without_metering
        .exports()
        .find(|e| e.name() == "wasmer_metering_remaining_points")
        .is_some()
    {
        return Err(VmError::BadExports);
    }

    if module_without_metering
        .exports()
        .find(|e| e.name() == "wasmer_metering_points_exhausted")
        .is_some()
    {
        return Err(VmError::BadExports);
    }

    check_exports(&module_without_metering)?;
    check_imports(&module_without_metering, max_memory_pages)?;

    Ok(())
}

fn check_exports(module: &Module) -> Result<(), VmError> {
    let mut allowed_exports: HashSet<_> = ["load", "save", "create", "call"].into_iter().collect();

    let mut required_exports: HashSet<_> = ["load", "save", "create"].into_iter().collect();

    for export in module.exports() {
        if !allowed_exports.remove(export.name()) {
            return Err(VmError::BadImports);
        }
        required_exports.remove(export.name());

        let func_type = export.ty().func().ok_or(VmError::BadExports)?;
        if !func_type.params().is_empty() || !func_type.results().is_empty() {
            return Err(VmError::BadExports);
        }
    }

    if !required_exports.is_empty() {
        return Err(VmError::BadExports);
    }

    Ok(())
}

fn check_imports(module: &Module, max_memory_pages: usize) -> Result<(), VmError> {
    let mut allowed_imports: HashSet<_> = [
        "push",
        "pop",
        "abort",
        "deploy",
        "create",
        "call",
        "state",
        "class",
        "caller",
        "expect_sig",
        "fund",
        "memory",
    ]
    .into_iter()
    .collect();

    let mut required_imports: HashSet<_> = ["memory", "pop", "push"].into_iter().collect();

    for import in module.imports() {
        if !allowed_imports.remove(import.name()) {
            return Err(VmError::BadImports);
        }
        required_imports.remove(import.name());

        if import.name() == "memory" {
            if import.module() != "env" {
                return Err(VmError::BadImports);
            }

            let memory_type = import.ty().memory().ok_or(VmError::BadImports)?;
            if memory_type.minimum.0 < 1
                || memory_type.minimum.0 > max_memory_pages as u32
                || memory_type
                    .maximum
                    .is_some_and(|x| x.0 > max_memory_pages as u32)
                || memory_type.shared
            {
                return Err(VmError::BadImports);
            }
        } else {
            if import.module() != "vm" {
                return Err(VmError::BadImports);
            }

            let func_type = import.ty().func().ok_or(VmError::BadImports)?;
            if import.name() == "push" {
                if func_type.params().len() != 2
                    || func_type.params()[0] != Type::I32
                    || func_type.params()[1] != Type::I32
                    || !func_type.results().is_empty()
                {
                    return Err(VmError::BadImports);
                }
            } else if import.name() == "pop" {
                if func_type.params().len() != 2
                    || func_type.params()[0] != Type::I32
                    || func_type.params()[1] != Type::I32
                    || func_type.results().len() != 1
                    || func_type.results()[0] != Type::I32
                {
                    return Err(VmError::BadImports);
                }
            } else if import.name() == "abort" {
                if func_type.params().len() != 2
                    || func_type.params()[0] != Type::I32
                    || func_type.params()[1] != Type::I32
                    || !func_type.results().is_empty()
                {
                    return Err(VmError::BadImports);
                }
            } else if !func_type.params().is_empty() || !func_type.results().is_empty() {
                return Err(VmError::BadImports);
            }
        }
    }

    if !required_imports.is_empty() {
        return Err(VmError::BadImports);
    }

    Ok(())
}
