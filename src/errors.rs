#[derive(Debug)]
pub enum ExecuteError {
    OpVerifyFailed,
    Script(ScriptError),
    Stack(StackError),
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
    Stack(StackError),
}

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
