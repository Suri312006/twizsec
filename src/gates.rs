#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gates {
    pub offset: u64,
    pub length: u64,
    pub align: u64,
}

pub enum GatesError {
    OutsideBounds,
    Unaligned,
}

impl Gates {
    pub fn new(offset: u64, length: u64, align: u64) -> Self {
        Gates {
            offset,
            length,
            align,
        }
    }
}
