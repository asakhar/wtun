use std::{cell::UnsafeCell, ptr::null_mut};

use crate::{
  adapter::AdapterOpenDeviceObject,
  logger::{error, last_error},
  wmain::get_system_params,
  Adapter, MAX_IP_PACKET_SIZE,
};
use cutils::{check_handle, csizeof, inspection::GetPtrExt, unsafe_defer};
use winapi::{
  shared::{
    minwindef::{DWORD, FALSE, UCHAR, UINT, ULONG},
    ntdef::{HANDLE, LONG},
  },
  um::{
    handleapi::CloseHandle,
    ioapiset::DeviceIoControl,
    memoryapi::{VirtualAlloc, VirtualFree},
    minwinbase::{CRITICAL_SECTION, SECURITY_ATTRIBUTES},
    synchapi::{CreateEventW, DeleteCriticalSection, InitializeCriticalSectionAndSpinCount},
    winnt::{
      FILE_READ_DATA, FILE_WRITE_DATA, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    },
  },
};

const TUN_ALIGNMENT: ULONG = csizeof!(ULONG);
pub(crate) const fn tun_align(size: ULONG) -> ULONG {
  (size + (TUN_ALIGNMENT - 1)) & !(TUN_ALIGNMENT - 1)
}
pub(crate) fn tun_is_aligned<T: TryInto<ULONG> + Default>(size: T) -> bool {
  let size = size.try_into().unwrap_or_default();
  (size & (TUN_ALIGNMENT - 1)) == 0
}
const TUN_PACKET_SIZE: ULONG = csizeof!(TunPacket);
const TUN_RING_SIZE: ULONG = csizeof!(TunRing);
const TUN_MAX_PACKET_SIZE: ULONG = tun_align(TUN_PACKET_SIZE + MAX_IP_PACKET_SIZE);
pub(crate) fn tun_ring_capacity<T: TryInto<ULONG> + Default>(size: T) -> ULONG {
  let size = size.try_into().unwrap_or_default();
  size - TUN_RING_SIZE - (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT)
}
pub(crate) fn tun_ring_size(capacity: ULONG) -> usize {
  (TUN_RING_SIZE + (capacity) + (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT)) as usize
}
pub(crate) fn tun_ring_wrap<T1: TryInto<ULONG> + Default, T2: TryInto<ULONG> + Default>(
  value: T1,
  capacity: T2,
) -> ULONG {
  let capacity = capacity.try_into().unwrap_or_default();
  let value = value.try_into().unwrap_or_default();
  value & (capacity - 1)
}
const LOCK_SPIN_COUNT: DWORD = 0x10000;
const TUN_PACKET_RELEASE: DWORD = 0x80000000;

#[repr(C)]
struct TunPacket {
  size: ULONG,
  data: [UCHAR; 0],
}

#[repr(C)]
struct TunRing {
  head: UnsafeCell<ULONG>,
  tail: UnsafeCell<ULONG>,
  alertable: UnsafeCell<LONG>,
  data: [UCHAR; 0],
}

const fn ctl_code(device_type: UINT, function: UINT, method: UINT, access: UINT) -> UINT {
  ((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method)
}

const METHOD_BUFFERED: UINT = 0;
const TUN_IOCTL_REGISTER_RINGS: UINT = ctl_code(
  51820,
  0x970,
  METHOD_BUFFERED,
  FILE_READ_DATA | FILE_WRITE_DATA,
);

#[repr(transparent)]
pub struct Event(pub HANDLE);

impl Drop for Event {
  fn drop(&mut self) {
    unsafe { CloseHandle(self.0) };
  }
}

#[repr(C)]
struct TunRegisterRing {
  ring_size: ULONG,
  ring: *mut TunRing,
  tail_moved: Event,
}

#[repr(C)]
struct TunRegisterRings {
  send: TunRegisterRing,
  recv: TunRegisterRing,
}

impl TunRegisterRings {
  fn new(
    security_attributes: &mut SECURITY_ATTRIBUTES,
    region: *mut u8,
    ring_size_usize: usize,
  ) -> std::io::Result<Self> {
    let ring_size = ring_size_usize as ULONG;
    let tail_moved = unsafe { CreateEventW(security_attributes, FALSE, FALSE, null_mut()) };
    if !check_handle(tail_moved) {
      return Err(last_error!("Failed to create send event"));
    }
    let tail_moved = Event(tail_moved);
    let send = TunRegisterRing {
      ring_size,
      ring: region.cast(),
      tail_moved,
    };
    let tail_moved = unsafe { CreateEventW(security_attributes, FALSE, FALSE, null_mut()) };
    if !check_handle(tail_moved) {
      return Err(last_error!("Failed to create receive event"));
    };
    let tail_moved = Event(tail_moved);
    let recv = TunRegisterRing {
      ring_size,
      ring: unsafe { region.add(ring_size_usize) }.cast(),
      tail_moved,
    };
    Ok(Self { send, recv })
  }
}
#[repr(C)]
struct SessionRecv {
  tail: ULONG,
  tail_release: ULONG,
  packets_to_release: ULONG,
  lock: CRITICAL_SECTION,
}
#[repr(C)]

struct SessionSend {
  head: ULONG,
  head_release: ULONG,
  packets_to_release: ULONG,
  lock: CRITICAL_SECTION,
}

#[repr(C)]
pub struct Session {
  capacity: ULONG,
  recv: SessionRecv,
  send: SessionSend,
  descriptor: TunRegisterRings,
  handle: HANDLE,
}

impl Session {
  fn new(descriptor: TunRegisterRings, handle: HANDLE, capacity: ULONG) -> Self {
    let recv =  unsafe { std::mem::zeroed() } ;
    let send =  unsafe { std::mem::zeroed() } ;
    Self {
      descriptor,
      handle,
      capacity,
      recv,
      send
    }
  }
}

pub(crate) fn WintunStartSession(
  adapter: &mut Adapter,
  capacity: DWORD,
) -> std::io::Result<Session> {
  let system_params = unsafe { get_system_params() };
  let ring_size = tun_ring_size(capacity);
  let allocated_region: *mut u8 = unsafe {
    VirtualAlloc(
      null_mut(),
      ring_size * 2,
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE,
    )
  }
  .cast();
  if allocated_region.is_null() {
    return Err(last_error!(
      "Failed to allocate ring memory (requested size: 0x{:x})",
      ring_size * 2
    ));
  }
  unsafe_defer! { cleanupRegion <-
    VirtualFree(allocated_region.cast(), 0, MEM_RELEASE);
  };
  let descriptor = TunRegisterRings::new(
    &mut system_params.SecurityAttributes,
    allocated_region,
    ring_size,
  )?;
  let handle = match AdapterOpenDeviceObject(adapter) {
    Ok(res) => res,
    Err(err) => {
      return Err(error!(err, "Failed to open adapter device object"));
    }
  };
  let mut session = Session::new(descriptor, handle, capacity);
  cleanupRegion.forget();
  let mut BytesReturned: DWORD = 0;
  if FALSE
    == unsafe {
      DeviceIoControl(
        session.handle,
        TUN_IOCTL_REGISTER_RINGS,
        session.descriptor.get_mut_ptr().cast(),
        csizeof!(TunRegisterRings),
        null_mut(),
        0,
        &mut BytesReturned,
        null_mut(),
      )
    }
  {
    return Err(last_error!("Failed to register rings"));
  }
  session.capacity = capacity;
  unsafe { InitializeCriticalSectionAndSpinCount(&mut session.recv.lock, LOCK_SPIN_COUNT) };
  unsafe { InitializeCriticalSectionAndSpinCount(&mut session.send.lock, LOCK_SPIN_COUNT) };
  Ok(session)
}

impl Drop for Session {
  fn drop(&mut self) {
    WintunEndSession(self)
  }
}

pub(crate) fn WintunEndSession(session: &mut Session) {
  unsafe {
    DeleteCriticalSection(&mut session.send.lock);
    DeleteCriticalSection(&mut session.recv.lock);
    CloseHandle(session.handle);
    VirtualFree(session.descriptor.send.ring.cast(), 0, MEM_RELEASE);
  }
}

pub(crate) fn WintunGetReadWaitEvent(session: &Session) -> &Event {
  &session.descriptor.send.tail_moved
}
pub(crate) fn WintunGetWriteWaitEvent(session: &Session) -> &Event {
  &session.descriptor.recv.tail_moved
}

