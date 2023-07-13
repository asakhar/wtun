#![allow(dead_code, unused_unsafe)]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
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
mod rundll32;
mod session;
mod winapi_ext;
mod wintun_inf;
mod wmain;

pub use adapter::Adapter;
pub use driver::get_running_driver_version;
pub use logger::{set_logger, LogLevel};
pub use session::{Event, RecvPacket, RecvPacketRead, SendPacket, SendPacketWrite, Session, IoError};

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
    value.try_into()
  }
  pub unsafe fn new_unchecked(value: ULONG) -> Self {
    Self(value)
  }
}

pub enum RingCapacityError {
  TooBig,
  TooSmall,
  NotAPowerOfTwo,
}

impl TryFrom<ULONG> for RingCapacity {
  type Error = RingCapacityError;

  fn try_from(value: ULONG) -> Result<Self, Self::Error> {
    if value < MIN_RING_CAPACITY {
      return Err(Self::Error::TooSmall);
    }
    if value > MAX_RING_CAPACITY {
      return Err(Self::Error::TooBig);
    }
    if !value.is_power_of_two() {
      return Err(Self::Error::NotAPowerOfTwo);
    }
    Ok(Self(value))
  }
}

impl TryFrom<usize> for RingCapacity {
  type Error = RingCapacityError;

  fn try_from(value: usize) -> Result<Self, Self::Error> {
    if value < MIN_RING_CAPACITY as usize {
      return Err(Self::Error::TooSmall);
    }
    if value > MAX_RING_CAPACITY as usize {
      return Err(Self::Error::TooBig);
    }
    let value = value as ULONG;
    if !value.is_power_of_two() {
      return Err(Self::Error::NotAPowerOfTwo);
    }
    Ok(Self(value))
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
  pub fn new(value: ULONG) -> Result<Self, PacketSizeError> {
    value.try_into()
  }
  pub unsafe fn new_unchecked(value: ULONG) -> Self {
    Self(value)
  }
}

pub enum PacketSizeError {
  IsNul,
  TooBig,
}

impl TryFrom<ULONG> for PacketSize {
  type Error = PacketSizeError;

  fn try_from(value: ULONG) -> Result<Self, Self::Error> {
    if value == 0 {
      return Err(Self::Error::IsNul);
    }
    if value > MAX_IP_PACKET_SIZE {
      return Err(Self::Error::TooBig);
    }
    Ok(Self(value))
  }
}

impl TryFrom<usize> for PacketSize {
  type Error = PacketSizeError;

  fn try_from(value: usize) -> Result<Self, Self::Error> {
    if value == 0 {
      return Err(Self::Error::IsNul);
    }
    if value > MAX_IP_PACKET_SIZE as usize {
      return Err(Self::Error::TooBig);
    }
    let value = value as ULONG;
    Ok(Self(value))
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
