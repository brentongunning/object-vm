#[derive(Debug)]
pub enum ExecuteError {
    DivideByZero,
    OpVerifyFailed,
    Script(ScriptError),
    Stack(StackError),
    Verify(VerifyError),
    Vm(VmError),
}

#[derive(Debug)]
pub enum ScriptError {
    BadConditional,
    BadOpcode,
    UnexpectedEndOfScript,
}

#[derive(Debug)]
pub enum StackError {
    Underflow,
    Overflow,
    BadElement,
}

#[derive(Debug)]
pub enum VerifyError {
    BadIndex,
    BadPubKey,
    BadSignature,
    Script(ScriptError),
}

#[derive(Debug)]
pub enum VmError {
    // TODO: Remove this and replace with real errors
    Placeholder(String),
    Stack(StackError),
    Wasm(WasmError),
}

#[derive(Debug)]
pub enum WasmError {}

impl From<ScriptError> for ExecuteError {
    fn from(e: ScriptError) -> Self {
        ExecuteError::Script(e)
    }
}

impl From<StackError> for ExecuteError {
    fn from(e: StackError) -> Self {
        ExecuteError::Stack(e)
    }
}

impl From<VerifyError> for ExecuteError {
    fn from(e: VerifyError) -> Self {
        ExecuteError::Verify(e)
    }
}

impl From<VmError> for ExecuteError {
    fn from(e: VmError) -> Self {
        ExecuteError::Vm(e)
    }
}

impl From<ScriptError> for VerifyError {
    fn from(e: ScriptError) -> Self {
        VerifyError::Script(e)
    }
}

impl From<StackError> for VmError {
    fn from(e: StackError) -> Self {
        VmError::Stack(e)
    }
}

impl From<WasmError> for VmError {
    fn from(e: WasmError) -> Self {
        VmError::Wasm(e)
    }
}
