use std::fmt;

use bitfield_struct::bitfield;

#[test]
fn members() {
    /// A test bitfield with documentation
    #[bitfield(u64)]
    #[derive(PartialEq, Eq)] // <- Attributes after `bitfield` are carried over
    struct MyBitfield {
        /// Defaults to 16 bits for u16
        int: u16,
        /// Interpreted as 1 bit flag, with a custom default value
        #[bits(default = true)]
        flag: bool,
        /// Custom bit size
        #[bits(1)]
        tiny: u8,
        /// Sign extend for signed integers
        #[bits(13)]
        negative: i16,
        /// Supports any type with `into_bits`/`from_bits` functions
        #[bits(16)]
        custom: CustomEnum,
        /// Public field -> public accessor functions
        #[bits(10)]
        pub public: usize,
        /// Also supports read-only fields
        #[bits(1, access = RO)]
        read_only: bool,
        /// And write-only fields
        #[bits(1, access = WO)]
        write_only: bool,
        /// Padding
        #[bits(5)]
        __: u8,
    }

    /// A custom enum
    #[derive(Debug, PartialEq, Eq)]
    #[repr(u64)]
    enum CustomEnum {
        A = 0,
        B = 1,
        C = 2,
    }
    impl CustomEnum {
        const fn into_bits(self) -> u64 {
            self as _
        }
        const fn from_bits(value: u64) -> Self {
            match value {
                0 => Self::A,
                1 => Self::B,
                _ => Self::C,
            }
        }
    }

    let mut val = MyBitfield::new()
        .with_int(3 << 15)
        .with_tiny(1)
        .with_negative(-3)
        .with_public(2)
        // Would not compile
        // .with_read_only(true)
        .with_write_only(false);

    println!("{val:?}");

    let raw: u64 = val.into();
    println!("{raw:b}");

    assert_eq!(val.custom(), CustomEnum::A);
    val.set_custom(CustomEnum::B);

    assert_eq!(val.int(), 3 << 15);
    assert_eq!(val.flag(), true); // from default
    assert_eq!(val.negative(), -3);
    assert_eq!(val.tiny(), 1);
    assert_eq!(val.custom(), CustomEnum::B);
    assert_eq!(val.public(), 2);
    assert_eq!(val.read_only(), false);

    // const members
    assert_eq!(MyBitfield::FLAG_BITS, 1);
    assert_eq!(MyBitfield::FLAG_OFFSET, 16);

    val.set_negative(1);
    assert_eq!(val.negative(), 1);

    let pte = val.with_flag(false);
    assert_eq!(pte.flag(), false);
}

#[test]
fn attrs() {
    /// We have a custom default
    #[bitfield(u64, default = false)]
    #[derive(PartialEq, Eq)]
    struct Full {
        data: u64,
    }
    impl Default for Full {
        fn default() -> Self {
            Self(0)
        }
    }

    let full = Full::default();
    assert_eq!(u64::from(full), u64::from(Full::new()));

    let full = Full::new().with_data(u64::MAX);
    assert_eq!(full.data(), u64::MAX);
    assert!(full == Full::new().with_data(u64::MAX));
}

#[test]
fn debug() {
    /// We have a custom debug implementation -> opt out
    #[bitfield(u64, debug = false)]
    struct Full {
        data: u64,
    }

    impl fmt::Debug for Full {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "0x{:x}", self.data())
        }
    }

    let full = Full::new().with_data(123);
    println!("{full:?}");
}

#[test]
fn positive() {
    #[bitfield(u32)]
    struct MyBitfield {
        #[bits(3)]
        positive: u32,
        #[bits(29)]
        __: (),
    }

    let v = MyBitfield::new().with_positive(0);
    assert_eq!(v.positive(), 0);
    let v = MyBitfield::new().with_positive(1);
    assert_eq!(v.positive(), 1);
    let v = MyBitfield::new().with_positive(7);
    assert_eq!(v.positive(), 7);
}

#[test]
fn negative() {
    #[bitfield(u32)]
    struct MyBitfield {
        #[bits(3)]
        negative: i32,
        #[bits(29)]
        __: (),
    }

    let v = MyBitfield::new().with_negative(-3);
    assert_eq!(v.negative(), -3);
    let v = MyBitfield::new().with_negative(0);
    assert_eq!(v.negative(), 0);
    let v = MyBitfield::new().with_negative(3);
    assert_eq!(v.negative(), 3);
    let v = MyBitfield::new().with_negative(-4);
    assert_eq!(v.negative(), -4);
}

#[test]
#[should_panic]
fn negative_pos_overflow() {
    #[bitfield(u32)]
    struct MyBitfield {
        #[bits(3)]
        negative: i32,
        #[bits(29)]
        __: (),
    }

    MyBitfield::new().with_negative(4);
}

#[test]
#[should_panic]
fn negative_neg_overflow() {
    #[bitfield(u32)]
    struct MyBitfield {
        #[bits(3)]
        negative: i32,
        #[bits(29)]
        __: (),
    }

    MyBitfield::new().with_negative(-5);
}

#[test]
fn negative_signed() {
    #[bitfield(u64)]
    struct MyBitfield {
        negative: i32,
        #[bits(10)]
        positive: u16,
        #[bits(22)]
        __: u32,
    }

    let val = MyBitfield::new()
        .with_negative(-1)
        .with_positive(0b11_1111_1111);
    assert_eq!(val.negative(), -1);
    assert_eq!(val.positive(), 0b11_1111_1111);
}

#[test]
fn entirely_negative() {
    #[bitfield(u32)]
    struct MyBitfield {
        negative: i32,
    }

    let v = MyBitfield::new().with_negative(-3);
    assert_eq!(v.negative(), -3);
    let v = MyBitfield::new().with_negative(0);
    assert_eq!(v.negative(), 0);
    let v = MyBitfield::new().with_negative(3);
    assert_eq!(v.negative(), 3);
    let v = MyBitfield::new().with_negative(i32::MIN);
    assert_eq!(v.negative(), i32::MIN);
    let v = MyBitfield::new().with_negative(i32::MAX);
    assert_eq!(v.negative(), i32::MAX);
}

#[test]
fn custom() {
    #[bitfield(u16)]
    #[derive(PartialEq, Eq)]
    struct Bits {
        /// Supports any type, with default/to/from expressions
        /// - into/from call Bits::into_bits/Bits::from_bits if nothing else is specified
        /// - default falls back to calling Bits::from_bits with 0
        #[bits(13, default = CustomEnum::B, from = CustomEnum::my_from_bits)]
        custom: CustomEnum,
        // Padding with default
        #[bits(3)]
        __: (),
    }

    #[derive(Debug, PartialEq, Eq)]
    #[repr(u16)]
    enum CustomEnum {
        A = 0,
        B = 1,
        C = 2,
    }
    impl CustomEnum {
        // This has to be a const fn
        const fn into_bits(self) -> u16 {
            self as _
        }
        const fn my_from_bits(value: u16) -> Self {
            match value {
                0 => Self::A,
                1 => Self::B,
                _ => Self::C,
            }
        }
    }
}

#[test]
fn defaults() {
    #[bitfield(u16)]
    #[derive(PartialEq, Eq)]
    struct MyBitfield {
        /// Interpreted as 1-bit flag, with custom default
        #[bits(default = true)]
        flag: bool,
        /// Supports any type, with default/to/from expressions (that are const eval)
        /// - into/from call #ty::into_bits/#ty::from_bits if nothing else is specified
        #[bits(13, default = CustomEnum::B, from = CustomEnum::my_from_bits)]
        custom: CustomEnum,
        // Padding with default
        #[bits(2, default = 0b10)]
        __: (),
    }

    /// A custom enum
    #[derive(Debug, PartialEq, Eq)]
    #[repr(u16)]
    enum CustomEnum {
        A = 0,
        B = 1,
        C = 2,
    }
    impl CustomEnum {
        // This has to be const eval
        const fn into_bits(self) -> u16 {
            self as _
        }
        const fn my_from_bits(value: u16) -> Self {
            match value {
                0 => Self::A,
                1 => Self::B,
                _ => Self::C,
            }
        }
    }

    // Uses defaults
    let val = MyBitfield::new();

    assert_eq!(val.flag(), true);
    assert_eq!(val.custom(), CustomEnum::B);
    assert_eq!(val.0 >> 14, 0b10); // padding
}

#[test]
fn default_padding() {
    #[bitfield(u32)]
    struct MyBitfield {
        value: u16,
        #[bits(15, default = 0xfff)]
        __: (),
        #[bits(default = true)]
        __: bool,
    }
    let v = MyBitfield::new().with_value(0xff);

    assert_eq!(v.0, 0x8fff_00ff);
}

#[test]
fn lsb_order() {
    #[bitfield(u32, order=lsb)]
    struct MyBitfield {
        short: u16,
        #[bits(8)]
        __: (),
        byte: u8,
    }

    let v = MyBitfield::new().with_short(0xe11e).with_byte(0xf0);

    assert_eq!(v.0, 0xf0_00_e11e);
}

#[test]
fn msb_order() {
    #[bitfield(u32, order=msb)]
    struct MyBitfield {
        short: u16,
        #[bits(8)]
        __: (),
        byte: u8,
    }

    let v = MyBitfield::new().with_short(0xe11e).with_byte(0xf0);

    assert_eq!(v.0, 0xe11e_00_f0);
}
