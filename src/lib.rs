#![allow(dead_code, unused_unsafe)]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
use std::net::{Ipv4Addr, Ipv6Addr};

pub use winapi::shared::ifdef::NET_LUID;
pub use winapi::shared::minwindef::ULONG;

mod adapter;
mod adapter_win7;
mod driver;
mod logger;
mod namespace;
mod nci;
mod ntdll;
mod registry;
mod resource;
#[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
mod rundll32;
#[cfg(not(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64")))]
mod rundll32 {}
mod session;
mod winapi_ext;
mod wintun_inf;
mod wmain;

pub use adapter::{Adapter, ConstructsAndProvidesAdapter};
pub use driver::get_running_driver_version;
pub use logger::{set_logger, LogLevel};
pub use session::{
  Event, IoError, RecvPacket, RecvPacketRead, SendPacket, SendPacketWrite, Session,
};

pub const MIN_RING_CAPACITY: ULONG = 0x20000;
pub const MAX_RING_CAPACITY: ULONG = 0x4000000;
pub const MAX_IP_PACKET_SIZE: ULONG = 0xFFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RingCapacity(ULONG);

impl RingCapacity {
  pub const fn inner(self) -> ULONG {
    self.0
  }
}

impl RingCapacity {
  pub fn new(value: ULONG) -> Result<Self, RingCapacityError> {
    if value < MIN_RING_CAPACITY {
      return Err(RingCapacityError::TooSmall);
    }
    if value > MAX_RING_CAPACITY {
      return Err(RingCapacityError::TooBig);
    }
    if !value.is_power_of_two() {
      return Err(RingCapacityError::NotAPowerOfTwo);
    }
    Ok(Self(value))
  }
  pub const unsafe fn new_unchecked(value: ULONG) -> Self {
    Self(value)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingCapacityError {
  TooBig,
  TooSmall,
  NotAPowerOfTwo,
}

impl std::fmt::Display for RingCapacityError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::TooBig => "Choosen capacity is too big (consider MAX_RING_CAPACITY)",
      Self::TooSmall => "Choosen capacity is too small (consider MIN_RING_CAPACITY)",
      Self::NotAPowerOfTwo => "Choosen capacity is not a power of two",
    })
  }
}

impl TryFrom<ULONG> for RingCapacity {
  type Error = RingCapacityError;

  fn try_from(value: ULONG) -> Result<Self, Self::Error> {
    Self::new(value)
  }
}

impl TryFrom<usize> for RingCapacity {
  type Error = RingCapacityError;

  fn try_from(value: usize) -> Result<Self, Self::Error> {
    Self::new(value.try_into().ok().ok_or(Self::Error::TooBig)?)
  }
}

#[macro_export]
macro_rules! ring_capacity {
  ($cap:expr) => {{
    const CAP: $crate::ULONG = {
      assert!($cap >= $crate::MIN_RING_CAPACITY);
      assert!($cap <= $crate::MAX_RING_CAPACITY);
      assert!($cap.is_power_of_two());
      $cap
    };
    unsafe { $crate::RingCapacity::new_unchecked(CAP) }
  }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketSize(ULONG);

impl PacketSize {
  pub const fn inner(self) -> ULONG {
    self.0
  }
}

impl PacketSize {
  pub const fn new(value: ULONG) -> Result<Self, PacketSizeError> {
    if value == 0 {
      return Err(PacketSizeError::IsZero);
    }
    if value > MAX_IP_PACKET_SIZE {
      return Err(PacketSizeError::TooBig);
    }
    Ok(Self(value))
  }
  pub const unsafe fn new_unchecked(value: ULONG) -> Self {
    Self(value)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSizeError {
  IsZero,
  TooBig,
}

impl std::fmt::Display for PacketSizeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::TooBig => "Packet is too big (consider MAX_IP_PACKET_SIZE)",
      Self::IsZero => "Packet size can not be zero",
    })
  }
}

impl TryFrom<ULONG> for PacketSize {
  type Error = PacketSizeError;

  fn try_from(value: ULONG) -> Result<Self, Self::Error> {
    Self::new(value)
  }
}

impl TryFrom<usize> for PacketSize {
  type Error = PacketSizeError;

  fn try_from(value: usize) -> Result<Self, Self::Error> {
    Self::new(value.try_into().ok().ok_or(Self::Error::TooBig)?)
  }
}

#[macro_export]
macro_rules! packet_size {
  ($size:expr) => {{
    const SIZE: $crate::ULONG = {
      assert!($size != 0);
      assert!($size <= $crate::MAX_IP_PACKET_SIZE);
      $size
    };
    unsafe { $crate::PacketSize::new_unchecked(SIZE) }
  }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMaskPrefixError {
  InvalidInput,
}

impl std::fmt::Display for IpMaskPrefixError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("Invalid ip mask prefix. It should be in range 0..=32 or 0..=128 for Ipv4 and Ipv6 respectively")
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4MaskPrefix(u8);

impl TryFrom<u8> for Ipv4MaskPrefix {
  type Error = IpMaskPrefixError;
  fn try_from(value: u8) -> Result<Self, Self::Error> {
    Self::new(value)
  }
}

impl Ipv4MaskPrefix {
  pub const fn new(mask: u8) -> Result<Self, IpMaskPrefixError> {
    if mask > 32 {
      return Err(IpMaskPrefixError::InvalidInput);
    }
    Ok(Self(mask))
  }
  pub const unsafe fn new_unchecked(mask: u8) -> Self {
    Self(mask)
  }
  pub const fn mask(self) -> u8 {
    self.0
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv6MaskPrefix(u8);

impl TryFrom<u8> for Ipv6MaskPrefix {
  type Error = IpMaskPrefixError;
  fn try_from(value: u8) -> Result<Self, Self::Error> {
    Self::new(value)
  }
}

impl Ipv6MaskPrefix {
  pub const fn new(mask: u8) -> Result<Self, IpMaskPrefixError> {
    if mask > 128 {
      return Err(IpMaskPrefixError::InvalidInput);
    }
    Ok(Self(mask))
  }
  pub const unsafe fn new_unchecked(mask: u8) -> Self {
    Self(mask)
  }
  pub const fn mask(self) -> u8 {
    self.0
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAndMaskPrefix {
  V4 {
    ip: Ipv4Addr,
    prefix: Ipv4MaskPrefix,
  },
  V6 {
    ip: Ipv6Addr,
    prefix: Ipv6MaskPrefix,
  },
}

pub const fn parse_ipv4(data: &str) -> Ipv4Addr {
  let mut data = data.as_bytes();
  let mut octets = [0u8; 4];
  let mut octet = 0;
  let mut prev_dot = true;
  loop {
    let ch;
    (ch, data) = match data {
      [first, rest @ ..] => (*first, rest),
      [] => break,
    };
    match ch {
      b'0'..=b'9' => {
        prev_dot = false;
        octets[octet] *= 10;
        octets[octet] += ch - b'0';
      }
      b'.' => {
        if prev_dot {
          panic!("expected numeric value. found '.'")
        }
        octet += 1
      }
      b' ' => {}
      _ => panic!("invalid character"),
    }
    if octet == 4 {
      panic!("too many octets")
    }
  }
  Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
}

pub const fn parse_u16_hex(data: &str) -> u16 {
  let mut data = data.as_bytes();
  let mut num: u32 = 0;
  loop {
    let ch;
    (ch, data) = match data {
      [first, rest @ ..] => (*first, rest),
      [] => break,
    };
    match ch {
      b'0'..=b'9' => {
        num *= 16;
        num += (ch - b'0') as u32;
      }
      b'a'..=b'f' => {
        num *= 16;
        num += (ch - b'a') as u32 + 10;
      }
      b'A'..=b'F' => {
        num *= 16;
        num += (ch - b'A') as u32 + 10;
      }
      b' ' => {}
      _ => panic!("invalid character"),
    }
    if num > u16::MAX as u32 {
      panic!("expected at most 4 hex digits")
    }
  }
  num as u16
}

#[macro_export]
macro_rules! ip_mask {
  ($p1:literal . $p2:literal . $p3:literal . $p4:literal / $prefix:literal) => {{
    const ip: ::std::net::Ipv4Addr = $crate::parse_ipv4(stringify!($p1 . $p2 . $p3 . $p4));
    const prefix: $crate::Ipv4MaskPrefix = match $crate::Ipv4MaskPrefix::new($prefix) {
      Ok(res) => res,
      _ => panic!("Invalid mask prefix"),
    };
    $crate::IpAndMaskPrefix::V4 { ip, prefix }
  }};
  ($p1:literal . $p2:literal . $p3:literal / $prefix:literal) => {{
    const ip: ::std::net::Ipv4Addr = $crate::parse_ipv4(stringify!($p1 . $p2 . $p3));
    const prefix: $crate::Ipv4MaskPrefix = match $crate::Ipv4MaskPrefix::new($prefix) {
      Ok(res) => res,
      _ => panic!("Invalid mask prefix"),
    };
    $crate::IpAndMaskPrefix::V4 { ip, prefix }
  }};
  ($p1:literal . $p2:literal / $prefix:literal) => {{
    const ip: ::std::net::Ipv4Addr = $crate::parse_ipv4(stringify!($p1 . $p2));
    const prefix: $crate::Ipv4MaskPrefix = match $crate::Ipv4MaskPrefix::new($prefix) {
      Ok(res) => res,
      _ => panic!("Invalid mask prefix"),
    };
    $crate::IpAndMaskPrefix::V4 { ip, prefix }
  }};
  ($($i1:ident)?$($l1:literal)?:$($i2:ident)?$($l2:literal)?:$($i3:ident)?$($l3:literal)?:$($i4:ident)?$($l4:literal)?:$($i5:ident)?$($l5:literal)?:$($i6:ident)?$($l6:literal)?:$($i7:ident)?$($l7:literal)?:$($i8:ident)?$($l8:literal)?/$prefix:literal) => {
    {
      const ip: ::std::net::Ipv6Addr = ::std::net::Ipv6Addr::new(
        $crate::parse_u16_hex(stringify!($($i1)?$($l1)?)),
        $crate::parse_u16_hex(stringify!($($i2)?$($l2)?)),
        $crate::parse_u16_hex(stringify!($($i3)?$($l3)?)),
        $crate::parse_u16_hex(stringify!($($i4)?$($l4)?)),
        $crate::parse_u16_hex(stringify!($($i5)?$($l5)?)),
        $crate::parse_u16_hex(stringify!($($i6)?$($l6)?)),
        $crate::parse_u16_hex(stringify!($($i7)?$($l7)?)),
        $crate::parse_u16_hex(stringify!($($i8)?$($l8)?)),
      );
      const prefix: $crate::Ipv6MaskPrefix = match $crate::Ipv6MaskPrefix::new($prefix) {
        Ok(res) => res,
        _ => panic!("Invalid mask prefix"),
      };
      $crate::IpAndMaskPrefix::V6{ip, prefix}
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_macro_ipv4() {
    const IP_AND_MASK: IpAndMaskPrefix = ip_mask!(192.168.0 .10 / 24);
    assert_eq!(
      IP_AND_MASK,
      IpAndMaskPrefix::V4 {
        ip: Ipv4Addr::new(192, 168, 0, 10),
        prefix: Ipv4MaskPrefix(24)
      }
    )
  }
  #[test]
  fn test_macro_ipv6() {
    const IP_AND_MASK: IpAndMaskPrefix = ip_mask!(dead:beef:babe:cafe:0123:4567:89ab:cdef / 33);
    assert_eq!(
      IP_AND_MASK,
      IpAndMaskPrefix::V6 {
        ip: Ipv6Addr::new(0xdead, 0xbeef, 0xbabe, 0xcafe, 0x0123, 0x4567, 0x89ab, 0xcdef),
        prefix: Ipv6MaskPrefix(33)
      }
    )
  }
}
