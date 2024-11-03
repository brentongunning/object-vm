#[derive(Debug)]
pub enum ExecuteError {}

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
}

#[derive(Debug)]
pub enum VerifyError {
    BadIndex,
    Script(ScriptError),
}

#[derive(Debug)]
pub enum VmError {
    Stack(StackError),
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
