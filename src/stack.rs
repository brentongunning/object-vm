use crate::errors::StackError;

pub trait Stack {
    fn push(&mut self, buf: &[u8]) -> Result<(), StackError>;
    fn top(&self) -> Option<&[u8]>;
    fn drop(&mut self, index: usize) -> Result<(), StackError>;
    fn swap(&mut self, index: usize) -> Result<(), StackError>;
    fn depth(&self) -> usize;
    fn to_alt(&mut self) -> Result<(), StackError>;
    fn from_alt(&mut self) -> Result<(), StackError>;
    fn clear(&mut self);
}

pub struct StackImpl {
    stack: Vec<Vec<u8>>,
    alt: Vec<Vec<u8>>,
}

impl StackImpl {
    pub fn new() -> Self {
        StackImpl {
            stack: Vec::new(),
            alt: Vec::new(),
        }
    }
}

impl Stack for StackImpl {
    fn push(&mut self, buf: &[u8]) -> Result<(), StackError> {
        self.stack.push(buf.to_vec());
        Ok(())
    }

    fn top(&self) -> Option<&[u8]> {
        self.stack.last().map(|v| v.as_slice())
    }

    fn drop(&mut self, index: usize) -> Result<(), StackError> {
        if index >= self.stack.len() {
            return Err(StackError::Underflow);
        }
        let index = self.stack.len() - 1 - index;
        self.stack.remove(index);
        Ok(())
    }

    fn swap(&mut self, index: usize) -> Result<(), StackError> {
        if index >= self.stack.len() {
            return Err(StackError::Underflow);
        }
        let index = self.stack.len() - 1 - index;
        let index2 = self.stack.len() - 1;
        self.stack.swap(index, index2);
        Ok(())
    }

    fn depth(&self) -> usize {
        self.stack.len()
    }

    fn to_alt(&mut self) -> Result<(), StackError> {
        if let Some(top) = self.stack.pop() {
            self.alt.push(top);
            Ok(())
        } else {
            Err(StackError::Underflow)
        }
    }

    fn from_alt(&mut self) -> Result<(), StackError> {
        if let Some(top) = self.alt.pop() {
            self.stack.push(top);
            Ok(())
        } else {
            Err(StackError::Underflow)
        }
    }

    fn clear(&mut self) {
        self.stack.clear();
        self.alt.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stack() {
        let stack = StackImpl::new();
        assert_eq!(stack.depth(), 0);
    }

    #[test]
    fn push() {
        let mut stack = StackImpl::new();
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.top().unwrap(), &[4, 5, 6]);
        stack.drop(0).unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn top() {
        let mut stack = StackImpl::new();
        assert_eq!(stack.top(), None);
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn drop() {
        let mut stack = StackImpl::new();
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.drop(0).unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        assert!(stack.drop(1).is_err());
    }

    #[test]
    fn swap() {
        let mut stack = StackImpl::new();
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.swap(1).unwrap();
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        stack.swap(1).unwrap();
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.top().unwrap(), &[4, 5, 6]);
        assert!(stack.swap(2).is_err());
    }

    #[test]
    fn depth() {
        let mut stack = StackImpl::new();
        assert_eq!(stack.depth(), 0);
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.depth(), 1);
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.depth(), 2);
        stack.drop(0).unwrap();
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn to_alt() {
        let mut stack = StackImpl::new();
        assert!(stack.to_alt().is_err());
        stack.push(&[1, 2, 3]).unwrap();
        stack.to_alt().unwrap();
        assert_eq!(stack.depth(), 0);
        assert_eq!(stack.alt.len(), 1);
        assert_eq!(stack.alt[0], [1, 2, 3]);
    }

    #[test]
    fn from_alt() {
        let mut stack = StackImpl::new();
        assert!(stack.from_alt().is_err());
        stack.alt.push([1, 2, 3].to_vec());
        stack.from_alt().unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.top().unwrap(), &[1, 2, 3]);
        assert_eq!(stack.alt.len(), 0);
    }

    #[test]
    fn clear() {
        let mut stack = StackImpl::new();
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.to_alt().unwrap();
        stack.clear();
        assert_eq!(stack.depth(), 0);
        assert_eq!(stack.alt.len(), 0);
    }
}
