use crate::errors::StackError;
use num_bigint::{BigInt, Sign};
use std::mem::size_of;

pub trait Stack {
    fn clear(&mut self);
    fn push(&mut self, buf: &[u8]) -> Result<(), StackError>;
    fn pop<T>(&mut self, f: impl FnOnce(&[u8]) -> T) -> Result<T, StackError>;
    fn last<T>(&mut self, f: impl FnOnce(&[u8]) -> T) -> Result<T, StackError>;
    fn dup(&mut self, index: usize) -> Result<(), StackError>;
    fn swap(&mut self, index: usize) -> Result<(), StackError>;
    fn depth(&self) -> usize;
    fn move_to_alt_stack(&mut self) -> Result<(), StackError>;
    fn move_from_alt_stack(&mut self) -> Result<(), StackError>;
}

pub struct StackImpl {
    stack: Vec<Vec<u8>>,
    alt: Vec<Vec<u8>>,
    max_total_size: usize,
    max_element_size: usize,
    max_elements: usize,
    size: usize,
}

impl StackImpl {
    pub fn new(max_total_size: usize, max_element_size: usize, max_elements: usize) -> Self {
        Self {
            stack: Vec::new(),
            alt: Vec::new(),
            max_total_size,
            max_element_size,
            max_elements,
            size: 0,
        }
    }
}

impl Stack for StackImpl {
    fn clear(&mut self) {
        self.stack.clear();
        self.alt.clear();
        self.size = 0;
    }

    fn push(&mut self, buf: &[u8]) -> Result<(), StackError> {
        if self.size + buf.len() > self.max_total_size {
            return Err(StackError::Overflow);
        }
        if buf.len() > self.max_element_size {
            return Err(StackError::Overflow);
        }
        if self.stack.len() + self.alt.len() + 1 > self.max_elements {
            return Err(StackError::Overflow);
        }
        self.stack.push(buf.to_vec());
        self.size += buf.len();
        Ok(())
    }

    fn pop<T>(&mut self, f: impl FnOnce(&[u8]) -> T) -> Result<T, StackError> {
        match self.stack.pop() {
            Some(v) => {
                self.size -= v.len();
                Ok(f(v.as_slice()))
            }
            None => Err(StackError::Underflow),
        }
    }

    fn last<T>(&mut self, f: impl FnOnce(&[u8]) -> T) -> Result<T, StackError> {
        match self.stack.last() {
            Some(v) => Ok(f(v.as_slice())),
            None => Err(StackError::Underflow),
        }
    }

    fn dup(&mut self, count: usize) -> Result<(), StackError> {
        if count > self.stack.len() {
            return Err(StackError::Underflow);
        }
        for i in self.stack.len() - count..self.stack.len() {
            self.push(&self.stack[i].clone())?;
        }
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

    fn move_to_alt_stack(&mut self) -> Result<(), StackError> {
        if let Some(top) = self.stack.pop() {
            self.alt.push(top);
            Ok(())
        } else {
            Err(StackError::Underflow)
        }
    }

    fn move_from_alt_stack(&mut self) -> Result<(), StackError> {
        if let Some(top) = self.alt.pop() {
            self.stack.push(top);
            Ok(())
        } else {
            Err(StackError::Underflow)
        }
    }
}

pub fn decode_bool(elem: &[u8]) -> bool {
    elem.iter().any(|&x| x != 0)
}

pub fn encode_bool(b: bool) -> Vec<u8> {
    if b {
        vec![1]
    } else {
        vec![]
    }
}

pub fn decode_bigint(elem: &[u8]) -> BigInt {
    BigInt::from_signed_bytes_le(elem)
}

pub fn encode_bigint(n: BigInt) -> Vec<u8> {
    if n.sign() == Sign::NoSign {
        vec![]
    } else {
        n.to_signed_bytes_le()
    }
}

pub fn decode_num<T: TryFrom<u64>>(elem: &[u8]) -> Result<T, StackError> {
    let bigint = decode_bigint(elem);
    let (sign, digits) = bigint.to_u64_digits();
    if sign == Sign::Minus || digits.len() > 1 {
        return Err(StackError::BadElement);
    }
    let num_u64 = *digits.first().unwrap_or(&0);
    num_u64.try_into().map_err(|_| StackError::BadElement)
}

pub fn decode_arr<T>(elem: &[u8]) -> Result<T, StackError>
where
    T: Sized + Default + AsMut<[u8]>,
{
    if elem.len() != size_of::<T>() {
        return Err(StackError::BadElement);
    }
    let mut arr = Default::default();
    <T as AsMut<[u8]>>::as_mut(&mut arr).clone_from_slice(elem);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stack() {
        let stack = StackImpl::new(1024, 256, 32);
        assert_eq!(stack.depth(), 0);
    }

    #[test]
    fn push() {
        let mut stack = StackImpl::new(1024, 256, 32);
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.push(&[7, 8, 9]).unwrap();
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![7, 8, 9]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn push_oom() {
        let mut stack = StackImpl::new(1024, 256, 5);
        let r = stack.push(&[0; 257]);
        assert!(matches!(r, Err(StackError::Overflow)));
        stack.push(&[0; 256]).unwrap();
        stack.push(&[0; 256]).unwrap();
        stack.push(&[0; 256]).unwrap();
        stack.push(&[0; 128]).unwrap();
        let r = stack.push(&[0; 256]);
        assert!(matches!(r, Err(StackError::Overflow)));
        stack.push(&[0; 1]).unwrap();
        let r = stack.push(&[0; 1]);
        assert!(matches!(r, Err(StackError::Overflow)));
    }

    #[test]
    fn pop() {
        let mut stack = StackImpl::new(1024, 256, 32);
        let r = stack.pop(|x| x.to_vec());
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn last() {
        let mut stack = StackImpl::new(1024, 256, 32);
        let r = stack.last(|x| x.to_vec());
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.last(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert_eq!(stack.last(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
    }

    #[test]
    fn dup() {
        let mut stack = StackImpl::new(1024, 256, 32);
        stack.dup(0).unwrap();
        stack.push(&[1, 2, 3]).unwrap();
        stack.dup(1).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.dup(2).unwrap();
        assert_eq!(
            stack.stack,
            vec![
                vec![1, 2, 3],
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![1, 2, 3],
                vec![4, 5, 6]
            ]
        );
        stack.dup(3).unwrap();
        assert_eq!(
            stack.stack,
            vec![
                vec![1, 2, 3],
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![4, 5, 6],
                vec![1, 2, 3],
                vec![4, 5, 6],
            ]
        );
    }

    #[test]
    fn dup_oom() {
        let mut stack = StackImpl::new(1024, 1024, 32);
        stack.push(&[0; 400]).unwrap();
        stack.push(&[0; 400]).unwrap();
        assert!(matches!(stack.dup(2), Err(StackError::Overflow)));
    }

    #[test]
    fn swap() {
        let mut stack = StackImpl::new(1024, 256, 32);
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.swap(1).unwrap();
        assert_eq!(stack.depth(), 2);
        assert!(matches!(stack.swap(2), Err(StackError::Underflow)));
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![4, 5, 6]);
        assert!(matches!(stack.swap(0), Err(StackError::Underflow)));
        assert!(matches!(stack.swap(1), Err(StackError::Underflow)));
    }

    #[test]
    fn depth() {
        let mut stack = StackImpl::new(1024, 256, 32);
        assert_eq!(stack.depth(), 0);
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.depth(), 1);
        stack.push(&[4, 5, 6]).unwrap();
        assert_eq!(stack.depth(), 2);
        stack.pop(|_| {}).unwrap();
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn move_to_alt_stack() {
        let mut stack = StackImpl::new(1024, 256, 32);
        let r = stack.move_to_alt_stack();
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[1, 2, 3]).unwrap();
        stack.move_to_alt_stack().unwrap();
        assert_eq!(stack.depth(), 0);
        assert_eq!(stack.alt.len(), 1);
        assert_eq!(stack.alt[0], [1, 2, 3]);
    }

    #[test]
    fn move_from_alt_stack() {
        let mut stack = StackImpl::new(1024, 256, 32);
        let r = stack.move_from_alt_stack();
        assert!(matches!(r, Err(StackError::Underflow)));
        stack.push(&[1, 2, 3]).unwrap();
        assert_eq!(stack.depth(), 1);
        stack.move_to_alt_stack().unwrap();
        assert_eq!(stack.depth(), 0);
        stack.move_from_alt_stack().unwrap();
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.pop(|x| x.to_vec()).unwrap(), vec![1, 2, 3]);
        assert_eq!(stack.alt.len(), 0);
    }

    #[test]
    fn clear() {
        let mut stack = StackImpl::new(1024, 256, 32);
        stack.push(&[1, 2, 3]).unwrap();
        stack.push(&[4, 5, 6]).unwrap();
        stack.move_to_alt_stack().unwrap();
        stack.clear();
        assert_eq!(stack.depth(), 0);
        assert_eq!(stack.alt.len(), 0);
    }

    #[test]
    fn decode_bool() {
        use super::decode_bool;
        assert!(!decode_bool(&[]));
        assert!(!decode_bool(&[0]));
        assert!(decode_bool(&[1]));
        assert!(!decode_bool(&[0, 0, 0]));
        assert!(decode_bool(&[0, 0, 1]));
    }

    #[test]
    fn encode_bool() {
        use super::encode_bool;
        assert_eq!(encode_bool(false), vec![]);
        assert_eq!(encode_bool(true), vec![1]);
    }

    #[test]
    fn decode_bigint() {
        use super::decode_bigint;
        assert_eq!(decode_bigint(&[]), BigInt::from(0));
        assert_eq!(decode_bigint(&[0]), BigInt::from(0));
        assert_eq!(decode_bigint(&[1]), BigInt::from(1));
        assert_eq!(decode_bigint(&[1, 0, 0]), BigInt::from(1));
        assert_eq!(decode_bigint(&[1, 0, 0, 0]), BigInt::from(1));
        assert_eq!(decode_bigint(&[1, 0, 0, 0, 0]), BigInt::from(1));
        assert_eq!(decode_bigint(&[0xff]), BigInt::from(-1));
        assert_eq!(decode_bigint(&[0xff, 0xff]), BigInt::from(-1));
        assert_eq!(decode_bigint(&[0xfe, 0xff, 0xff]), BigInt::from(-2));
    }

    #[test]
    fn encode_bigint() {
        use super::encode_bigint;
        assert_eq!(encode_bigint(BigInt::from(0)), vec![]);
        assert_eq!(encode_bigint(BigInt::from(1)), vec![1]);
        assert_eq!(encode_bigint(BigInt::from(255)), vec![255, 0]);
        assert_eq!(encode_bigint(BigInt::from(256)), vec![0, 1]);
        assert_eq!(encode_bigint(BigInt::from(-1)), vec![0xff]);
        assert_eq!(encode_bigint(BigInt::from(-2)), vec![0xfe]);
    }

    #[test]
    fn decode_arr() {
        use super::decode_arr;
        assert_eq!(decode_arr::<[u8; 3]>(&[1, 2, 3]).unwrap(), [1, 2, 3]);
        let r = decode_arr::<[u8; 3]>(&[1, 2, 3, 4]);
        assert!(matches!(r, Err(StackError::BadElement)));
    }
}
