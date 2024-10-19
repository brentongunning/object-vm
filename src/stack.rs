pub trait Stack {
    fn push(&mut self, buf: &[u8]) -> Result<(), Error>;
    fn top(&self) -> Option<&[u8]>;
    fn drop(&mut self, n: usize) -> Result<(), Error>;
    fn swap(&mut self, n: usize) -> Result<(), Error>;
    fn depth(&self) -> usize;
    fn to_alt(&mut self) -> Result<(), Error>;
    fn from_alt(&mut self) -> Result<(), Error>;
    fn clear(&mut self);
}

pub enum Error {
    Underflow,
    Overflow,
}
