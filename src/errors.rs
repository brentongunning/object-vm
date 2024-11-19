use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use wasmer::CompileError;

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
    ExceededBytecodeLength,
    InvalidCoin,
    MissingUniquifier,
    // TODO: Remove this and replace with real errors
    Placeholder(String),
    Stack(StackError),
    Unsigned,
    Wasm(WasmError),
}

#[derive(Debug)]
pub enum WasmError {
    BadExports,
    BadImports,
    Compile(CompileError),
    NotFound,
}

impl Error for ExecuteError {}
impl Error for ScriptError {}
impl Error for StackError {}
impl Error for VerifyError {}
impl Error for VmError {}
impl Error for WasmError {}

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

impl From<CompileError> for WasmError {
    fn from(e: CompileError) -> Self {
        WasmError::Compile(e)
    }
}

impl Display for ExecuteError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ExecuteError::DivideByZero => write!(f, "Divide by zero"),
            ExecuteError::OpVerifyFailed => write!(f, "OP_VERIFY failed"),
            ExecuteError::Script(e) => write!(f, "Script error: {}", e),
            ExecuteError::Stack(e) => write!(f, "Stack error: {}", e),
            ExecuteError::Verify(e) => write!(f, "Verify error: {}", e),
            ExecuteError::Vm(e) => write!(f, "Vm error: {}", e),
        }
    }
}

impl Display for ScriptError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ScriptError::BadConditional => write!(f, "Bad conditional"),
            ScriptError::BadOpcode => write!(f, "Bad opcode"),
            ScriptError::UnexpectedEndOfScript => write!(f, "Unexpected end of script"),
        }
    }
}

impl Display for StackError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            StackError::Underflow => write!(f, "Stack underflow"),
            StackError::Overflow => write!(f, "Stack overflow"),
            StackError::BadElement => write!(f, "Bad element"),
        }
    }
}

impl Display for VerifyError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            VerifyError::BadIndex => write!(f, "Bad index"),
            VerifyError::BadPubKey => write!(f, "Bad public key"),
            VerifyError::BadSignature => write!(f, "Bad signature"),
            VerifyError::Script(e) => write!(f, "Script error: {}", e),
        }
    }
}

impl Display for VmError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            VmError::ExceededBytecodeLength => write!(f, "Exceeded bytecode length"),
            VmError::InvalidCoin => write!(f, "Invalid coin"),
            VmError::MissingUniquifier => write!(f, "Missing uniquifier"),
            VmError::Placeholder(s) => write!(f, "Placeholder: {}", s),
            VmError::Stack(e) => write!(f, "Stack error: {}", e),
            VmError::Unsigned => write!(f, "Unsigned"),
            VmError::Wasm(e) => write!(f, "Wasm error: {:?}", e),
        }
    }
}

impl Display for WasmError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            WasmError::BadExports => write!(f, "Bad exports"),
            WasmError::BadImports => write!(f, "Bad imports"),
            WasmError::Compile(e) => write!(f, "Compile error: {:?}", e),
            WasmError::NotFound => write!(f, "Output not found"),
        }
    }
}
