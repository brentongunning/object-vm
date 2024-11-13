use std::io::{self, Read, Write};

pub const ID_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

pub const TX_VERSION: u8 = 1;

pub const OUTPUT_CLASS: u8 = 0;
pub const OUTPUT_OBJECT: u8 = 1;

pub type Id = [u8; ID_LEN];
pub type Hash = [u8; HASH_LEN];
pub type PubKey = [u8; PUBKEY_LEN];
pub type Sig = [u8; SIG_LEN];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u8,
    pub script: Vec<u8>,
}

pub enum Output {
    Class {
        code: Vec<u8>,
    },
    Object {
        class_id: Id,
        revision_id: Id,
        state: Vec<u8>,
    },
}

impl Default for Tx {
    fn default() -> Self {
        Tx {
            version: TX_VERSION,
            script: vec![],
        }
    }
}

impl Tx {
    pub fn id(&self) -> Id {
        blake3d(&self.to_vec())
    }
}

impl ReadWrite for Tx {
    fn write(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&[self.version])?;
        write_varint(w, self.script.len() as u64)?;
        w.write_all(&self.script)
    }

    fn read(r: &mut impl Read) -> io::Result<Self> {
        let mut version = [0];
        r.read_exact(&mut version)?;
        let version = version[0];
        if version != TX_VERSION {
            Err(io::Error::new(io::ErrorKind::InvalidData, "bad version"))?;
        }

        let len = read_varint(r)?;
        let mut script = vec![0; len as usize];
        r.read_exact(&mut script)?;

        Ok(Tx { version, script })
    }
}

impl Output {
    pub fn id(&self) -> Id {
        blake3d(&self.to_vec())
    }
}

impl ReadWrite for Output {
    fn write(&self, w: &mut impl Write) -> io::Result<()> {
        match self {
            Output::Class { code } => {
                w.write_all(&[OUTPUT_CLASS])?;
                write_varint(w, code.len() as u64)?;
                w.write_all(code)
            }
            Output::Object {
                class_id,
                revision_id,
                state,
            } => {
                w.write_all(&[OUTPUT_OBJECT])?;
                w.write_all(class_id)?;
                w.write_all(revision_id)?;
                write_varint(w, state.len() as u64)?;
                w.write_all(state)
            }
        }
    }

    fn read(r: &mut impl Read) -> io::Result<Self> {
        let mut buf = [0; 1];
        r.read_exact(&mut buf)?;
        match buf[0] {
            OUTPUT_CLASS => {
                let len = read_varint(r)?;
                let mut code = vec![0; len as usize];
                r.read_exact(&mut code)?;
                Ok(Output::Class { code })
            }
            OUTPUT_OBJECT => {
                let mut class_id = [0; ID_LEN];
                r.read_exact(&mut class_id)?;
                let mut revision_id = [0; ID_LEN];
                r.read_exact(&mut revision_id)?;
                let len = read_varint(r)?;
                let mut state = vec![0; len as usize];
                r.read_exact(&mut state)?;
                Ok(Output::Object {
                    class_id,
                    revision_id,
                    state,
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad output type",
            )),
        }
    }
}

pub fn blake3d(data: &[u8]) -> Hash {
    blake3::hash(blake3::hash(data).as_bytes()).into()
}

pub trait ReadWrite {
    fn write(&self, w: &mut impl Write) -> io::Result<()>;

    fn read(r: &mut impl Read) -> io::Result<Self>
    where
        Self: Sized;

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.write(&mut buf).unwrap();
        buf
    }

    fn from_bytes(buf: &[u8]) -> io::Result<Self>
    where
        Self: Sized,
    {
        let mut cursor = io::Cursor::new(buf);
        let value = Self::read(&mut cursor)?;
        if cursor.position() as usize != buf.len() {
            Err(io::Error::new(io::ErrorKind::InvalidData, "extra data"))?;
        }
        Ok(value)
    }
}

pub fn write_varint(w: &mut impl Write, n: u64) -> io::Result<()> {
    if n < 0xfd {
        w.write_all(&[n as u8])
    } else if n <= 0xffff {
        w.write_all(&[0xfd])?;
        w.write_all(&(n as u16).to_le_bytes())
    } else if n <= 0xffffffff {
        w.write_all(&[0xfe])?;
        w.write_all(&(n as u32).to_le_bytes())
    } else {
        w.write_all(&[0xff])?;
        w.write_all(&n.to_le_bytes())
    }
}

pub fn read_varint(r: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0; 1];
    r.read_exact(&mut buf)?;
    let n = buf[0] as u64;
    if n < 0xfd {
        Ok(n)
    } else if n == 0xfd {
        let mut buf = [0; 2];
        r.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf) as u64)
    } else if n == 0xfe {
        let mut buf = [0; 4];
        r.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf) as u64)
    } else {
        let mut buf = [0; 8];
        r.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::*;

    struct FailingWriter {}

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "err"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingReader {}

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "err"))
        }
    }

    #[test]
    fn tx_id() {
        use super::blake3d;

        let mut tx = Tx::default();
        tx.script = vec![OP_1, OP_2, OP_3];
        assert_eq!(tx.id(), blake3d(&tx.to_vec()));

        let tx_id = "5aa5eeed98cee8ec588bcaf32c1a931009c3221bc8fdc6a50ab20f30f93c1d52";
        let tx_id: Id = hex::decode(tx_id).unwrap().try_into().unwrap();
        assert_eq!(&tx.id(), &tx_id);
    }

    #[test]
    fn tx_write() {
        assert_eq!(Tx::default().to_vec(), vec![1, 0]);

        let mut tx = Tx::default();
        tx.script = vec![OP_1, OP_2, OP_3];
        assert_eq!(tx.to_vec(), vec![1, 3, 81, 82, 83]);

        let mut tx = Tx::default();
        tx.script = vec![0; 258];
        assert_eq!(tx.to_vec(), [vec![1, 0xfd, 2, 1], vec![0; 258]].concat());

        assert!(tx.write(&mut FailingWriter {}).is_err());
    }

    #[test]
    fn tx_read() {
        let tx = Tx::from_bytes(&[1, 0]).unwrap();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.script, vec![]);

        let buf = vec![1, 3, 81, 82, 83];
        let tx = Tx::from_bytes(&buf).unwrap();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.script, vec![OP_1, OP_2, OP_3]);

        let buf = [vec![1, 0xfd, 2, 1], vec![0; 258]].concat();
        let tx = Tx::from_bytes(&buf).unwrap();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.script, vec![0; 258]);

        assert!(Tx::read(&mut FailingReader {}).is_err());

        assert!(Tx::from_bytes(&[]).is_err());
        assert!(Tx::from_bytes(&[0]).is_err());
        assert!(Tx::from_bytes(&[1]).is_err());
        assert!(Tx::from_bytes(&[1, 1]).is_err());
        assert!(Tx::from_bytes(&[1, 3, 1, 2]).is_err());
        assert!(Tx::from_bytes(&[0, 0]).is_err());
        assert!(Tx::from_bytes(&[2, 0]).is_err());
    }

    #[test]
    fn output_id() {
        use super::blake3d;

        let output = Output::Class {
            code: vec![OP_1, OP_2, OP_3],
        };
        assert_eq!(output.id(), blake3d(&output.to_vec()));

        let output_id = "57d2fca7ce2e14e0b4ac726307435051e5e8a2f4a79d030a486cc6c3f4d22265";
        let output_id: Id = hex::decode(output_id).unwrap().try_into().unwrap();
        assert_eq!(&output.id(), &output_id);

        let output = Output::Object {
            class_id: [1; ID_LEN],
            revision_id: [2; ID_LEN],
            state: vec![OP_1, OP_2, OP_3],
        };
        assert_eq!(output.id(), blake3d(&output.to_vec()));

        let output_id = "827f397c3efc694e2bafdc556c4cfea494b29492559774ce2775ab674e30833f";
        let output_id: Id = hex::decode(output_id).unwrap().try_into().unwrap();
        assert_eq!(&output.id(), &output_id);
    }

    #[test]
    fn read_write_to_vec() {
        struct Test {}

        impl ReadWrite for Test {
            fn write(&self, w: &mut impl Write) -> io::Result<()> {
                w.write_all(&[1, 2, 3, 4])
            }

            fn read(_: &mut impl Read) -> io::Result<Self> {
                unreachable!();
            }
        }

        let test = Test {};
        assert_eq!(test.to_vec(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn read_write_from_bytes() {
        struct Test {}

        impl ReadWrite for Test {
            fn write(&self, _: &mut impl Write) -> io::Result<()> {
                unreachable!();
            }

            fn read(r: &mut impl Read) -> io::Result<Self> {
                let mut buf = [0; 4];
                r.read_exact(&mut buf)?;
                assert_eq!(buf, [1, 2, 3, 4]);
                Ok(Test {})
            }
        }

        Test::from_bytes(&[1, 2, 3, 4]).unwrap();
        assert!(Test::from_bytes(&[]).is_err());
        assert!(Test::from_bytes(&[1, 2, 3, 4, 5]).is_err())
    }

    #[test]
    fn blake3d() {
        use super::blake3d;

        let data = b"";
        let hash = blake3d(data);
        let expected = "82878ed8a480ee41775636820e05a934ca5c747223ca64306658ee5982e6c227";
        assert_eq!(hex::encode(hash), expected);

        let data = b"hello world";
        let hash = blake3d(data);
        let expected = "642d9fa590c86290761657e9f2be8de96164f3a85177e8fbf698a1e5211576af";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn write_varint() {
        use super::write_varint;

        let mut buf = vec![];
        write_varint(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0]);
        buf.clear();

        write_varint(&mut buf, 0xfc).unwrap();
        assert_eq!(buf, vec![0xfc]);
        buf.clear();

        write_varint(&mut buf, 0xfd).unwrap();
        assert_eq!(buf, vec![0xfd, 0xfd, 0x00]);
        buf.clear();

        write_varint(&mut buf, 0xffff).unwrap();
        assert_eq!(buf, vec![0xfd, 0xff, 0xff]);
        buf.clear();

        write_varint(&mut buf, 0x10000).unwrap();
        assert_eq!(buf, vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        buf.clear();

        write_varint(&mut buf, 0xffffffff).unwrap();
        assert_eq!(buf, vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
        buf.clear();

        write_varint(&mut buf, 0x100000000).unwrap();
        let v = vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(buf, v,);
        buf.clear();

        write_varint(&mut buf, 0xffffffffffffffff).unwrap();
        let v = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(buf, v);
        buf.clear();

        assert!(write_varint(&mut FailingWriter {}, 0).is_err());
    }

    #[test]
    fn read_varint() {
        use super::read_varint;

        let mut buf = io::Cursor::new(vec![0]);
        assert_eq!(read_varint(&mut buf).unwrap(), 0);

        let mut buf = io::Cursor::new(vec![0xfc]);
        assert_eq!(read_varint(&mut buf).unwrap(), 0xfc);

        let mut buf = io::Cursor::new(vec![0xfd, 0xfd, 0x00]);
        assert_eq!(read_varint(&mut buf).unwrap(), 0xfd);

        let mut buf = io::Cursor::new(vec![0xfd, 0xff, 0xff]);
        assert_eq!(read_varint(&mut buf).unwrap(), 0xffff);

        let mut buf = io::Cursor::new(vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(read_varint(&mut buf).unwrap(), 0x10000);

        let mut buf = io::Cursor::new(vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(read_varint(&mut buf).unwrap(), 0xffffffff);

        let mut buf = io::Cursor::new(vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(read_varint(&mut buf).unwrap(), 0x100000000);

        let mut buf = io::Cursor::new(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(read_varint(&mut buf).unwrap(), u64::MAX);

        let mut buf = io::Cursor::new(vec![]);
        assert!(read_varint(&mut buf).is_err(),);

        let mut buf = io::Cursor::new(vec![0xfd, 0xfd]);
        assert!(read_varint(&mut buf).is_err(),);

        let mut buf = io::Cursor::new(vec![0xfe, 0xff, 0xff, 0xff]);
        assert!(read_varint(&mut buf).is_err(),);

        let mut buf = io::Cursor::new(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(read_varint(&mut buf).is_err(),);
    }
}
