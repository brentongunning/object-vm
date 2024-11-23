use crate::{
    core::{Id, Object, NULL_ID},
    errors::{StackError, VmError, WasmError},
    misc::ObjectProvider,
    stack::Stack,
    vm::Vm,
};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    ptr::NonNull,
    sync::Arc,
};
use wasmer::{
    imports,
    sys::{BaseTunables, EngineBuilder, Features},
    vm::{
        MemoryStyle, TableStyle, VMConfig, VMMemory, VMMemoryDefinition, VMTable, VMTableDefinition,
    },
    CompilerConfig, FunctionEnv, FunctionEnvMut, Imports, Memory, MemoryError, MemoryType, Module,
    RuntimeError, Singlepass, Store, TableType, Tunables, Type,
};
use wasmer_middlewares::Metering;

// Because of how wasmer is implemented [1], the wasm stack gets shared across instances
// and cannot be configured per-module. It's also specific to this wasm implementation.
// Consensus will dictate the actual max stack size, so we set it big enough to be reasonable,
// avoid infinite recursion, and process historical blocks.
// [1] https://github.com/wasmerio/wasmer/blob/d3f02cb3daa3c214a230c672cb7309fde0646db9/lib/vm/src/trap/traphandlers.rs#L689
const WASM_STACK_SIZE: usize = 1024 * 1024;

// TODO: Move to limits
const MAX_MEMORY_PAGES: usize = 1;

pub trait Wasm {
    fn reset(&mut self) -> Result<(), WasmError>;
    fn object_ids(&mut self, callback: impl FnMut(&Id)) -> Result<(), WasmError>;
    fn revision_ids(&mut self, callback: impl FnMut(&Id)) -> Result<(), WasmError>;

    fn deploy(&mut self, code: &[u8], class_id: &Id) -> Result<(), WasmError>;
    fn create(&mut self, class_id: &Id, instance_id: &Id) -> Result<(), WasmError>;
    fn call(&mut self, object_id: &Id) -> Result<(), WasmError>;
    fn state<T>(
        &mut self,
        object_id: &Id,
        callback: impl FnMut(&[u8]) -> T,
    ) -> Result<T, WasmError>;
    fn class<T>(&mut self, object_id: &Id, callback: impl FnMut(&Id) -> T) -> Result<T, WasmError>;
}

pub struct WasmImpl<P: ObjectProvider> {
    object_provider: P,
    store: Store,
    classes: HashMap<Id, Class>,
    instances: HashMap<Id, Instance>,
}

struct Class {
    code: Vec<u8>,
    deployed: bool,
    module: wasmer::Module,
    static_instance: Option<wasmer::Instance>,
}

struct Instance {
    class_id: Id,
    revision_id: Option<Id>,
    instance: wasmer::Instance,
}

impl<P: ObjectProvider> WasmImpl<P> {
    pub fn new(object_provider: P) -> Self {
        Self {
            object_provider,
            store: create_store(),
            classes: HashMap::new(),
            instances: HashMap::new(),
        }
    }
}

impl<P: ObjectProvider> Wasm for WasmImpl<P> {
    fn reset(&mut self) -> Result<(), WasmError> {
        self.classes.clear();
        self.instances.clear();

        Ok(())
    }

    fn object_ids(&mut self, mut callback: impl FnMut(&Id)) -> Result<(), WasmError> {
        self.classes
            .iter()
            .filter(|(_, class)| class.deployed)
            .for_each(|(id, _)| callback(id));

        self.instances.keys().for_each(callback);

        Ok(())
    }

    fn revision_ids(&mut self, callback: impl FnMut(&Id)) -> Result<(), WasmError> {
        self.instances
            .iter()
            .filter_map(|(_, instance)| instance.revision_id.as_ref())
            .for_each(callback);

        Ok(())
    }

    fn deploy(&mut self, code: &[u8], class_id: &Id) -> Result<(), WasmError> {
        check_wasm(code, MAX_MEMORY_PAGES)?;

        let module = Module::new(&self.store, code)?;

        let class = Class {
            code: code.to_vec(),
            deployed: true,
            module,
            static_instance: None,
        };

        self.classes.insert(*class_id, class);

        Ok(())
    }

    fn create(&mut self, class_id: &Id, instance_id: &Id) -> Result<(), WasmError> {
        if !self.classes.contains_key(class_id) {
            self.object_provider.object(class_id, |bytes| {
                if let Some(bytes) = bytes {
                    let code = Object::parse_state(bytes);

                    let class = Class {
                        code: code.to_vec(),
                        deployed: false,
                        module: Module::new(&self.store, code)?,
                        static_instance: None,
                    };

                    self.classes.insert(*class_id, class);

                    Ok(())
                } else {
                    Err(WasmError::ObjectNotFound(*class_id))
                }
            })?;
        }

        let class = self.classes.get(class_id).unwrap();

        let (instance, _memory) = create_instance(&mut self.store, &class.module)?;

        let instance = Instance {
            class_id: *class_id,
            revision_id: None,
            instance,
        };

        self.instances.insert(*instance_id, instance);

        // TODO: Call create

        return Ok(());
    }

    fn call(&mut self, _object_id: &Id) -> Result<(), WasmError> {
        if !self.instances.contains_key(_object_id) {
            // TODO: Load the object instance
        }

        // TODO: Call call
        // TODO: Static call?

        unimplemented!();
    }

    fn state<T>(
        &mut self,
        object_id: &Id,
        mut callback: impl FnMut(&[u8]) -> T,
    ) -> Result<T, WasmError> {
        if let Some(class) = self.classes.get(object_id) {
            return Ok(callback(&class.code));
        }

        // TODO: instances

        self.object_provider.object(object_id, |bytes| {
            if let Some(bytes) = bytes {
                Ok(callback(Object::parse_state(bytes)))
            } else {
                Err(WasmError::ObjectNotFound(*object_id))
            }
        })
    }

    fn class<T>(
        &mut self,
        object_id: &Id,
        mut callback: impl FnMut(&Id) -> T,
    ) -> Result<T, WasmError> {
        if self.classes.contains_key(object_id) {
            return Ok(callback(&NULL_ID));
        }

        if let Some(instance) = self.instances.get(object_id) {
            return Ok(callback(&instance.class_id));
        }

        self.object_provider.object(object_id, |bytes| {
            if let Some(bytes) = bytes {
                Ok(callback(Object::parse_class_id(bytes)))
            } else {
                Err(WasmError::ObjectNotFound(*object_id))
            }
        })
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

pub fn check_wasm(bytecode: &[u8], max_memory_pages: usize) -> Result<(), WasmError> {
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
        return Err(WasmError::BadExports);
    }

    if module_without_metering
        .exports()
        .find(|e| e.name() == "wasmer_metering_points_exhausted")
        .is_some()
    {
        return Err(WasmError::BadExports);
    }

    check_exports(&module_without_metering)?;
    check_imports(&module_without_metering, max_memory_pages)?;

    Ok(())
}

fn check_exports(module: &Module) -> Result<(), WasmError> {
    let mut allowed_exports: HashSet<_> = ["load", "save", "create", "call"].into_iter().collect();

    let mut required_exports: HashSet<_> = ["load", "save", "create"].into_iter().collect();

    for export in module.exports() {
        if !allowed_exports.remove(export.name()) {
            return Err(WasmError::BadImports);
        }
        required_exports.remove(export.name());

        let func_type = export.ty().func().ok_or(WasmError::BadExports)?;
        if !func_type.params().is_empty() || !func_type.results().is_empty() {
            return Err(WasmError::BadExports);
        }
    }

    if !required_exports.is_empty() {
        return Err(WasmError::BadExports);
    }

    Ok(())
}

fn check_imports(module: &Module, max_memory_pages: usize) -> Result<(), WasmError> {
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
        "checksig",
        "fund",
        "memory",
    ]
    .into_iter()
    .collect();

    let mut required_imports: HashSet<_> = ["memory", "pop", "push"].into_iter().collect();

    for import in module.imports() {
        if !allowed_imports.remove(import.name()) {
            return Err(WasmError::BadImports);
        }
        required_imports.remove(import.name());

        if import.name() == "memory" {
            if import.module() != "env" {
                return Err(WasmError::BadImports);
            }

            let memory_type = import.ty().memory().ok_or(WasmError::BadImports)?;
            if memory_type.minimum.0 < 1
                || memory_type.minimum.0 > max_memory_pages as u32
                || memory_type
                    .maximum
                    .is_some_and(|x| x.0 > max_memory_pages as u32)
                || memory_type.shared
            {
                return Err(WasmError::BadImports);
            }
        } else {
            if import.module() != "vm" {
                return Err(WasmError::BadImports);
            }

            let func_type = import.ty().func().ok_or(WasmError::BadImports)?;
            if import.name() == "push" {
                if func_type.params().len() != 2
                    || func_type.params()[0] != Type::I32
                    || func_type.params()[1] != Type::I32
                    || !func_type.results().is_empty()
                {
                    return Err(WasmError::BadImports);
                }
            } else if import.name() == "pop" {
                if func_type.params().len() != 2
                    || func_type.params()[0] != Type::I32
                    || func_type.params()[1] != Type::I32
                    || func_type.results().len() != 1
                    || func_type.results()[0] != Type::I32
                {
                    return Err(WasmError::BadImports);
                }
            } else if import.name() == "abort" {
                if func_type.params().len() != 2
                    || func_type.params()[0] != Type::I32
                    || func_type.params()[1] != Type::I32
                    || !func_type.results().is_empty()
                {
                    return Err(WasmError::BadImports);
                }
            } else if !func_type.params().is_empty() || !func_type.results().is_empty() {
                return Err(WasmError::BadImports);
            }
        }
    }

    if !required_imports.is_empty() {
        return Err(WasmError::BadImports);
    }

    Ok(())
}

fn create_instance(
    _store: &mut Store,
    _module: &Module,
) -> Result<(wasmer::Instance, wasmer::Memory), WasmError> {
    // TODO
    unimplemented!();
}

struct Env<M: Vm + Send> {
    vm_ptr: usize,
    mem_ptr: usize,
    mem_size: usize,
    phantom: PhantomData<M>,
}

impl<M: Vm + Send> Env<M> {
    fn vm(&self) -> &mut M {
        unsafe { &mut *(self.vm_ptr as *mut M) }
    }
}

fn create_imports<M: Vm + Send + 'static>(
    store: &mut Store,
    vm_ptr: usize,
    memory: Memory,
) -> Result<Imports, WasmError> {
    let env = FunctionEnv::new(
        store,
        Env::<M> {
            vm_ptr,
            mem_ptr: memory.view(store).data_ptr() as usize,
            mem_size: memory.view(store).data_size() as usize,
            phantom: PhantomData,
        },
    );

    let import_object = imports! {
        "env" => {
            "memory" => memory
        },
        "vm" => {
            "push" => wasmer::Function::new_typed_with_env(store, &env, push),
            "pop" => wasmer::Function::new_typed_with_env(store, &env, pop),
            "abort" => wasmer::Function::new_typed_with_env(store, &env, abort),
            "deploy" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().deploy()?) }),
            "create" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().create()?) }),
            "call" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().call()?) }),
            "state" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().state()?) }),
            "class" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().class()?) }),
            "caller" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().caller()?) }),
            "checksig" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().checksig()?) }),
            "fund" => wasmer::Function::new_typed_with_env(store, &env,
                |env: FunctionEnvMut<Env<M>>| -> Result<(), RuntimeError> { Ok(env.data().vm().fund()?) })
        }
    };

    Ok(import_object)
}

fn push<M: Vm + Send + 'static>(
    env: FunctionEnvMut<Env<M>>,
    ptr: i32,
    len: i32,
) -> Result<(), RuntimeError> {
    let ptr = ptr as u32 as usize;
    let len = len as u32 as usize;
    if env.data().mem_size < ptr + len {
        return Err(RuntimeError::new("out of bounds"));
    }
    let ptr = (env.data().mem_ptr + ptr) as *const u8;
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(env.data().vm().stack().push(slice)?)
}

fn pop<M: Vm + Send + 'static>(
    env: FunctionEnvMut<Env<M>>,
    ptr: i32,
    max_len: i32,
) -> Result<i32, RuntimeError> {
    let ptr = ptr as u32 as usize;
    let max_len = max_len as u32 as usize;
    env.data().vm().stack().pop(|buf| {
        if buf.len() > max_len || env.data().mem_size < (ptr + buf.len()) {
            return Err(RuntimeError::new("out of bounds"));
        }
        let src = buf.as_ptr();
        let dst = (env.data().mem_ptr + ptr) as *mut u8;
        unsafe { std::ptr::copy_nonoverlapping(src, dst, buf.len()) };
        Ok(buf.len() as i32)
    })?
}

fn abort<M: Vm + Send + 'static>(
    env: FunctionEnvMut<Env<M>>,
    ptr: i32,
    len: i32,
) -> Result<(), RuntimeError> {
    let ptr = ptr as u32 as usize;
    let len = len as u32 as usize;
    if env.data().mem_size < ptr + len {
        return Err(RuntimeError::new("abort with bad msg"));
    }
    let ptr = (env.data().mem_ptr + ptr) as *const u8;
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let error = std::str::from_utf8(slice).unwrap_or("abort with bad msg");
    Err(RuntimeError::new(error))
}

impl From<StackError> for RuntimeError {
    fn from(e: StackError) -> Self {
        RuntimeError::new(format!("{:?}", e))
    }
}

impl From<VmError> for RuntimeError {
    fn from(e: VmError) -> Self {
        RuntimeError::new(format!("{:?}", e))
    }
}
