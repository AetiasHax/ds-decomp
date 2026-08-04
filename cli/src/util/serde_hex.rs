use std::{fmt::LowerHex, marker::PhantomData, ops::Neg};

use num_traits::{Num, Signed, Zero};
use serde::{Deserialize, Serialize, de::Visitor};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Hex<T: HexTrait>(pub T);
pub trait HexTrait: LowerHex + Num {}
impl HexTrait for u32 {}

impl<T: HexTrait> Serialize for Hex<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format!("{:#x}", self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de, T: HexTrait> Deserialize<'de> for Hex<T> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(HexVisitor(PhantomData))
    }
}

struct HexVisitor<T: HexTrait>(PhantomData<T>);

impl<'de, T: HexTrait> Visitor<'de> for HexVisitor<T> {
    type Value = Hex<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string containing a hexadecimal integer starting with '0x'")
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let v = v.strip_prefix("0x").unwrap_or(v);
        match T::from_str_radix(v, 16) {
            Ok(value) => Ok(Hex(value)),
            Err(_) => Err(serde::de::Error::custom(format!("invalid hex integer format '{v}'"))),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct IHex<T: IHexTrait>(pub T);
pub trait IHexTrait: LowerHex + Neg + Copy + Signed + Zero {}
impl IHexTrait for i64 {}

impl<T: IHexTrait> Serialize for IHex<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = if self.0.is_negative() {
            format!("-{:#x}", -self.0)
        } else {
            format!("{:#x}", self.0)
        };
        serializer.serialize_str(&s)
    }
}

impl<T: IHexTrait> IHex<T> {
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<'de, T: IHexTrait> Deserialize<'de> for IHex<T> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(IHexVisitor(PhantomData))
    }
}

struct IHexVisitor<T: IHexTrait>(PhantomData<T>);

impl<'de, T: IHexTrait> Visitor<'de> for IHexVisitor<T> {
    type Value = IHex<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string containing a hexadecimal integer starting with '0x'")
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if let Some(v) = v.strip_prefix('-') {
            let v = v.strip_prefix("0x").unwrap_or(v);
            match T::from_str_radix(v, 16) {
                Ok(value) => Ok(IHex(-value)),
                Err(_) => {
                    Err(serde::de::Error::custom(format!("invalid hex integer format '{v}'")))
                }
            }
        } else {
            let v = v.strip_prefix("0x").unwrap_or(v);
            match T::from_str_radix(v, 16) {
                Ok(value) => Ok(IHex(value)),
                Err(_) => {
                    Err(serde::de::Error::custom(format!("invalid hex integer format '{v}'")))
                }
            }
        }
    }
}
