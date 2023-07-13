use std::{cell::UnsafeCell, pin::Pin, ptr::null_mut, sync::atomic::Ordering};

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
    ntdef::HANDLE,
    winerror::WAIT_TIMEOUT,
  },
  um::{
    handleapi::CloseHandle,
    ioapiset::DeviceIoControl,
    memoryapi::{VirtualAlloc, VirtualFree},
    minwinbase::{CRITICAL_SECTION, SECURITY_ATTRIBUTES},
    synchapi::{
      CreateEventW, DeleteCriticalSection, EnterCriticalSection,
      InitializeCriticalSectionAndSpinCount, LeaveCriticalSection, SetEvent, WaitForSingleObject,
    },
    winbase::{INFINITE, WAIT_FAILED, WAIT_OBJECT_0},
    winnt::{
      FILE_READ_DATA, FILE_WRITE_DATA, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    },
  },
};

const TUN_ALIGNMENT: ULONG = csizeof!(ULONG);
pub(crate) const fn tun_align(size: ULONG) -> ULONG {
  (size.wrapping_add(TUN_ALIGNMENT.wrapping_sub(1))) & !(TUN_ALIGNMENT.wrapping_sub(1))
}
pub(crate) fn tun_is_aligned(size: ULONG) -> bool {
  (size & (TUN_ALIGNMENT.wrapping_sub(1))) == 0
}
const TUN_PACKET_SIZE: ULONG = csizeof!(TunPacket);
const TUN_RING_SIZE: ULONG = csizeof!(TunRing);
const TUN_MAX_PACKET_SIZE: ULONG = tun_align(TUN_PACKET_SIZE.wrapping_add(MAX_IP_PACKET_SIZE));
pub(crate) const fn tun_ring_capacity(size: usize) -> ULONG {
  let size = size as ULONG;
  size
    .wrapping_sub(TUN_RING_SIZE)
    .wrapping_sub(TUN_MAX_PACKET_SIZE.wrapping_sub(TUN_ALIGNMENT))
}
pub(crate) const fn tun_ring_size(capacity: ULONG) -> usize {
  (TUN_RING_SIZE
    .wrapping_add(capacity)
    .wrapping_add(TUN_MAX_PACKET_SIZE.wrapping_sub(TUN_ALIGNMENT))) as usize
}
pub(crate) const fn tun_ring_wrap(value: ULONG, capacity: ULONG) -> ULONG {
  value & (capacity.wrapping_sub(1))
}
const LOCK_SPIN_COUNT: DWORD = 0x10000;
const TUN_PACKET_RELEASE: DWORD = 0x80000000;
const OFFSETOF_TUN_PACKET_DATA: isize = csizeof!(ULONG);

const __CHECK_OFFSETOF_TUN_PACKET_DATA: () = {
  assert!(OFFSETOF_TUN_PACKET_DATA == std::mem::size_of::<TunPacket>() as isize);
};

#[repr(C)]
struct TunPacket {
  size: ULONG,
  data: [UCHAR; 0],
}

const __CHECK_ATOMIC_U32: () = {
  assert!(std::mem::size_of::<ULONG>() == std::mem::size_of::<std::sync::atomic::AtomicU32>());
};

// #[cfg(target_has_atomic_load_store = "32")]
#[repr(C)]
struct TunRing {
  head: std::sync::atomic::AtomicU32,
  tail: std::sync::atomic::AtomicU32,
  alertable: std::sync::atomic::AtomicU32,
  data: [UCHAR; 0],
}

impl TunRing {
  unsafe fn get(&self, idx: ULONG) -> &TunPacket {
    &*self.data.as_ptr().add(idx as usize).cast()
  }
  unsafe fn get_mut(&mut self, idx: ULONG) -> &mut TunPacket {
    &mut *self.data.as_mut_ptr().add(idx as usize).cast()
  }
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

#[derive(Debug)]
#[repr(transparent)]
pub struct Event(pub HANDLE);

impl Event {
  fn new(security_attributes: &mut SECURITY_ATTRIBUTES) -> std::io::Result<Self> {
    let event = unsafe { CreateEventW(security_attributes, FALSE, FALSE, null_mut()) };
    if !check_handle(event) {
      return Err(std::io::Error::last_os_error());
    }
    Ok(Self(event))
  }
}

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

impl TunRegisterRing {
  fn ring(&self) -> &TunRing {
    unsafe { &*self.ring }
  }
  fn ring_mut(&self) -> &mut TunRing {
    unsafe { &mut *self.ring }
  }
}

#[repr(C)]
struct TunRegisterRings {
  send: TunRegisterRing,
  recv: TunRegisterRing,
}

impl TunRegisterRings {
  fn new(
    security_attributes: &mut SECURITY_ATTRIBUTES,
    ring_size_usize: usize,
  ) -> std::io::Result<Self> {
    let region: *mut u8 = unsafe {
      VirtualAlloc(
        null_mut(),
        ring_size_usize * 2,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
      )
    }
    .cast();
    if region.is_null() {
      return Err(last_error!(
        "Failed to allocate ring memory (requested size: 0x{:x})",
        ring_size_usize * 2
      ));
    }
    unsafe_defer! { cleanupRegion <-
      VirtualFree(region.cast(), 0, MEM_RELEASE);
    };
    let ring_size = ring_size_usize as ULONG;
    let tail_moved =
      Event::new(security_attributes).map_err(|err| error!(err, "Failed to create send event"))?;
    let send = TunRegisterRing {
      ring_size,
      ring: region.cast(),
      tail_moved,
    };
    let tail_moved = Event::new(security_attributes)
      .map_err(|err| error!(err, "Failed to create receive event"))?;
    let recv = TunRegisterRing {
      ring_size,
      ring: unsafe { region.add(ring_size_usize) }.cast(),
      tail_moved,
    };
    cleanupRegion.forget();
    Ok(Self { send, recv })
  }
}

impl Drop for TunRegisterRings {
  fn drop(&mut self) {
    unsafe { VirtualFree(self.send.ring.cast(), 0, MEM_RELEASE) };
  }
}

#[repr(transparent)]
struct CriticalSection(UnsafeCell<CRITICAL_SECTION>);
#[must_use]
struct CriticalSectionGuard<'a>(&'a CriticalSection);
impl<'a> Drop for CriticalSectionGuard<'a> {
  fn drop(&mut self) {
    unsafe { LeaveCriticalSection(self.0 .0.get()) };
  }
}
impl<'a> CriticalSectionGuard<'a> {
  fn leave(self) {
    drop(self)
  }
}
impl Default for CriticalSection {
  fn default() -> Self {
    Self(unsafe { std::mem::zeroed() })
  }
}
impl CriticalSection {
  unsafe fn init(&mut self) {
    InitializeCriticalSectionAndSpinCount(self.0.get(), LOCK_SPIN_COUNT);
  }
  unsafe fn enter<'a>(&'a self) -> CriticalSectionGuard<'a> {
    EnterCriticalSection(self.0.get());
    CriticalSectionGuard(self)
  }
}
impl Drop for CriticalSection {
  fn drop(&mut self) {
    unsafe { DeleteCriticalSection(self.0.get()) };
  }
}

#[derive(Default)]
#[repr(C)]
struct SessionRecv {
  tail: UnsafeCell<ULONG>,
  tail_release: UnsafeCell<ULONG>,
  packets_to_release: UnsafeCell<ULONG>,
  lock: CriticalSection,
}

#[derive(Default)]
#[repr(C)]
struct SessionSend {
  head: UnsafeCell<ULONG>,
  head_release: UnsafeCell<ULONG>,
  packets_to_release: UnsafeCell<ULONG>,
  lock: CriticalSection,
}

#[derive(Debug)]
#[repr(transparent)]
struct ObjectHandle(HANDLE);

impl Drop for ObjectHandle {
  fn drop(&mut self) {
    unsafe { CloseHandle(self.0) };
  }
}

impl ObjectHandle {
  fn open(adapter: &mut Adapter) -> std::io::Result<Self> {
    AdapterOpenDeviceObject(adapter)
      .map(ObjectHandle)
      .map_err(|err| error!(err, "Failed to open adapter device object"))
  }
}

#[repr(C)]
pub struct Session {
  capacity: ULONG,
  recv: SessionRecv,
  send: SessionSend,
  descriptor: TunRegisterRings,
  handle: ObjectHandle,
  recv_tail_moved: Event,
}

impl std::fmt::Debug for Session {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Session")
      .field("capacity", &self.capacity)
      .field("handle", &self.handle)
      .finish()
  }
}

impl Session {
  fn new(
    recv_tail_moved: Event,
    descriptor: TunRegisterRings,
    handle: ObjectHandle,
    capacity: ULONG,
  ) -> Pin<Box<Self>> {
    let recv = SessionRecv::default();
    let send = SessionSend::default();
    let mut session = Box::pin(Self {
      descriptor,
      handle,
      capacity,
      recv,
      send,
      recv_tail_moved,
    });
    unsafe { session.recv.lock.init() };
    unsafe { session.send.lock.init() };
    session
  }
}

pub(crate) fn WintunStartSession(
  adapter: &mut Adapter,
  capacity: DWORD,
) -> std::io::Result<Pin<Box<Session>>> {
  let system_params = unsafe { get_system_params() };
  let ring_size = tun_ring_size(capacity);
  let descriptor = TunRegisterRings::new(&mut system_params.SecurityAttributes, ring_size)?;
  let recv_tail_moved = Event::new(&mut system_params.SecurityAttributes)
    .map_err(|err| error!(err, "Failed to create dup recv event"))?;
  let handle = ObjectHandle::open(adapter)?;
  let mut session = Session::new(recv_tail_moved, descriptor, handle, capacity);
  let mut BytesReturned: DWORD = 0;
  if FALSE
    == unsafe {
      DeviceIoControl(
        session.handle.0,
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
  Ok(session)
}

impl Session {
  pub fn is_write_avaliable(&self) -> std::io::Result<bool> {
    let read_event = self.GetWriteWaitEvent();
    let res = unsafe { WaitForSingleObject(read_event.0, 0) };
    match res {
      WAIT_OBJECT_0 => Ok(true),
      WAIT_TIMEOUT => Ok(false),
      WAIT_FAILED => Err(std::io::Error::last_os_error()),
      other => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("WaitForSingleObject returned: {other}"),
      )),
    }
  }
  pub fn is_read_avaliable(&self) -> std::io::Result<bool> {
    let write_event = self.GetReadWaitEvent();
    let res = unsafe { WaitForSingleObject(write_event.0, 0) };
    match res {
      WAIT_OBJECT_0 => Ok(true),
      WAIT_TIMEOUT => Ok(false),
      WAIT_FAILED => Err(std::io::Error::last_os_error()),
      other => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("WaitForSingleObject returned: {other}"),
      )),
    }
  }
  pub fn block_until_read_avaliable(
    &self,
    timeout: Option<std::time::Duration>,
  ) -> std::io::Result<()> {
    let read_event = self.GetReadWaitEvent();
    let millis = timeout
      .as_ref()
      .map(std::time::Duration::as_millis)
      .map(|millis| {
        if millis > DWORD::MAX as u128 {
          None
        } else {
          Some(millis as DWORD)
        }
      })
      .flatten()
      .unwrap_or(INFINITE);
    let res = unsafe { WaitForSingleObject(read_event.0, millis) };
    match res {
      WAIT_OBJECT_0 => Ok(()),
      WAIT_TIMEOUT => Err(std::io::ErrorKind::TimedOut.into()),
      WAIT_FAILED => Err(std::io::Error::last_os_error()),
      other => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("WaitForSingleObject returned: {other}"),
      )),
    }
  }
  pub fn block_until_write_avaliable(
    &self,
    timeout: Option<std::time::Duration>,
  ) -> std::io::Result<()> {
    let write_event = self.GetWriteWaitEvent();
    let millis = timeout
      .as_ref()
      .map(std::time::Duration::as_millis)
      .map(|millis| {
        if millis > DWORD::MAX as u128 {
          None
        } else {
          Some(millis as DWORD)
        }
      })
      .flatten()
      .unwrap_or(INFINITE);
    let res = unsafe { WaitForSingleObject(write_event.0, millis) };
    match res {
      WAIT_OBJECT_0 => Ok(()),
      WAIT_TIMEOUT => Err(std::io::ErrorKind::TimedOut.into()),
      WAIT_FAILED => Err(std::io::Error::last_os_error()),
      other => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("WaitForSingleObject returned: {other}"),
      )),
    }
  }
  pub fn GetReadWaitEvent(&self) -> &Event {
    &self.descriptor.send.tail_moved
  }
  pub fn GetWriteWaitEvent(&self) -> &Event {
    &self.recv_tail_moved
  }
}

#[derive(Debug)]
pub struct RecvPacket<'a> {
  data: &'a mut [u8],
  session: &'a Session,
}

pub struct RecvPacketRead<'a, 'p>(&'p RecvPacket<'a>, usize);

impl<'a> RecvPacket<'a> {
  fn new(data: &'a mut [u8], session: &'a Session) -> Self {
    Self { data, session }
  }
  pub fn slice(&self) -> &[u8] {
    self.data
  }
  pub fn mut_slice(&mut self) -> &mut [u8] {
    self.data
  }
  pub fn read<'p>(&'p self) -> RecvPacketRead<'a, 'p> {
    RecvPacketRead(self, 0)
  }
  pub fn release(self) {
    drop(self)
  }
}

impl<'a, 'p> std::io::Read for RecvPacketRead<'a, 'p> {
  fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    if self.0.data.len() == self.1 {
      return Ok(0);
    }
    let read = std::cmp::min(buf.len(), self.0.data.len() - self.1);
    buf[0..read].copy_from_slice(&self.0.data[self.1..self.1 + read]);
    self.1 += read;
    Ok(read)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
  AdapterIsTerminating, // Adapter is terminating
  Exhausted,            // No more data in buffer | buffer is full
  InvalidData,          // Session buffer is corrupted
}

impl std::fmt::Display for IoError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::AdapterIsTerminating => "Adapter is terminating",
      Self::Exhausted => "No more data in the ring buffer or the buffer is full",
      Self::InvalidData => "Session ring buffer is corrupted",
    })
  }
}

impl std::error::Error for IoError {}

impl Session {
  pub fn recv<'a>(&'a self) -> Result<RecvPacket<'a>, IoError> {
    let guard = unsafe { self.send.lock.enter() };
    if unsafe { *self.send.head.get() } >= self.capacity {
      return Err(IoError::AdapterIsTerminating);
    }
    let buff_tail = self.descriptor.send.ring().tail.load(Ordering::Acquire);
    if buff_tail >= self.capacity {
      return Err(IoError::AdapterIsTerminating);
    }
    if unsafe { *self.send.head.get() } == buff_tail {
      return Err(IoError::Exhausted);
    }
    let buff_content = tun_ring_wrap(
      buff_tail.wrapping_sub(unsafe { *self.send.head.get() }),
      self.capacity,
    );
    if buff_content < csizeof!(TunPacket) {
      return Err(IoError::InvalidData);
    }
    let buff_packet = unsafe {
      self
        .descriptor
        .send
        .ring_mut()
        .get_mut(*self.send.head.get())
    };
    if buff_packet.size > MAX_IP_PACKET_SIZE {
      return Err(IoError::InvalidData);
    }
    let aligned_packet_size = tun_align(TUN_PACKET_SIZE.wrapping_add(buff_packet.size));
    if aligned_packet_size > buff_content {
      return Err(IoError::InvalidData);
    }
    let packet_size = buff_packet.size as usize;
    let packet =
      unsafe { std::slice::from_raw_parts_mut(buff_packet.data.as_mut_ptr(), packet_size) };
    unsafe {
      *self.send.head.get() = tun_ring_wrap(
        (*self.send.head.get()).wrapping_add(aligned_packet_size),
        self.capacity,
      )
    };
    unsafe { *self.send.packets_to_release.get() += 1 };
    guard.leave();
    Ok(RecvPacket::new(packet, self))
  }
}

impl<'a> Drop for RecvPacket<'a> {
  fn drop(&mut self) {
    let session = self.session;
    let guard = unsafe { session.send.lock.enter() };
    let release_buff_packet: &mut TunPacket = unsafe {
      &mut *self
        .data
        .as_mut_ptr()
        .offset(-OFFSETOF_TUN_PACKET_DATA)
        .cast()
    };
    release_buff_packet.size |= TUN_PACKET_RELEASE;
    while unsafe { *session.send.packets_to_release.get() } != 0 {
      let buff_packet = unsafe {
        session
          .descriptor
          .send
          .ring()
          .get(*session.send.head_release.get())
      };
      if (buff_packet.size & TUN_PACKET_RELEASE) == 0 {
        break;
      }
      let aligned_packet_size =
        tun_align(TUN_PACKET_SIZE.wrapping_add(buff_packet.size & !TUN_PACKET_RELEASE));
      unsafe {
        *session.send.head_release.get() = tun_ring_wrap(
          (*session.send.head_release.get()).wrapping_add(aligned_packet_size),
          session.capacity,
        )
      };
      unsafe { *session.send.packets_to_release.get() -= 1 };
    }
    session.descriptor.send.ring().head.store(
      unsafe { *session.send.head_release.get() },
      Ordering::Release,
    );
    guard.leave();
  }
}

#[derive(Debug)]
pub struct SendPacket<'a> {
  data: &'a mut [u8],
  session: &'a Session,
}
pub struct SendPacketWrite<'a, 'p>(&'p mut SendPacket<'a>, usize);

impl<'a, 'p> std::io::Write for SendPacketWrite<'a, 'p> {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    if self.0.data.len() == self.1 {
      return Ok(0);
    }
    let written = std::cmp::min(buf.len(), self.0.data.len() - self.1);
    self.0.data[self.1..self.1 + written].copy_from_slice(&buf[0..written]);
    self.1 += written;
    Ok(written)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl<'a> SendPacket<'a> {
  fn new(data: &'a mut [u8], session: &'a Session) -> Self {
    Self { data, session }
  }
  pub fn slice(&self) -> &[u8] {
    self.data
  }
  pub fn mut_slice(&mut self) -> &mut [u8] {
    self.data
  }
  pub fn write<'p>(&'p mut self) -> SendPacketWrite<'a, 'p> {
    SendPacketWrite(self, 0)
  }
  pub fn send(self) {
    drop(self)
  }
}

impl Session {
  pub fn allocate<'a>(&'a self, packet_size: DWORD) -> Result<SendPacket<'a>, IoError> {
    let guard = unsafe { self.recv.lock.enter() };
    if unsafe { *self.recv.tail.get() } >= self.capacity {
      return Err(IoError::AdapterIsTerminating);
    }
    let aligned_packet_size = tun_align(TUN_PACKET_SIZE.wrapping_add(packet_size));
    let buff_head = self.descriptor.recv.ring().head.load(Ordering::Acquire);
    if buff_head >= self.capacity {
      return Err(IoError::AdapterIsTerminating);
    }
    let buff_space = tun_ring_wrap(
      buff_head
        .wrapping_sub(unsafe { *self.recv.tail.get() })
        .wrapping_sub(TUN_ALIGNMENT),
      self.capacity,
    );
    if aligned_packet_size > buff_space {
      return Err(IoError::Exhausted);
    }
    let buff_packet = unsafe {
      self
        .descriptor
        .recv
        .ring_mut()
        .get_mut(*self.recv.tail.get())
    };
    buff_packet.size = packet_size | TUN_PACKET_RELEASE;
    let packet = unsafe {
      std::slice::from_raw_parts_mut(buff_packet.data.as_mut_ptr(), packet_size as usize)
    };
    unsafe {
      *self.recv.tail.get() = tun_ring_wrap(
        (*self.recv.tail.get()).wrapping_add(aligned_packet_size),
        self.capacity,
      )
    };
    unsafe { *self.recv.packets_to_release.get() += 1 };
    guard.leave();
    Ok(SendPacket::new(packet, self))
  }
}

impl<'a> Drop for SendPacket<'a> {
  fn drop(&mut self) {
    let session = self.session;
    let guard = unsafe { session.recv.lock.enter() };
    let released_buff_packet: &mut TunPacket = unsafe {
      &mut *self
        .data
        .as_mut_ptr()
        .offset(-OFFSETOF_TUN_PACKET_DATA)
        .cast()
    };
    released_buff_packet.size &= !TUN_PACKET_RELEASE;
    while unsafe { *session.recv.packets_to_release.get() } != 0 {
      let buff_packet = unsafe {
        session
          .descriptor
          .recv
          .ring()
          .get(*session.recv.tail_release.get())
      };
      if buff_packet.size & TUN_PACKET_RELEASE != 0 {
        break;
      }
      let aligned_packet_size = tun_align(TUN_PACKET_SIZE.wrapping_add(buff_packet.size));
      unsafe {
        *session.recv.tail_release.get() = tun_ring_wrap(
          (*session.recv.tail_release.get()).wrapping_add(aligned_packet_size),
          session.capacity,
        )
      };
      unsafe { *session.recv.packets_to_release.get() -= 1 };
    }
    if session.descriptor.recv.ring().tail.load(Ordering::Relaxed)
      != unsafe { *session.recv.tail_release.get() }
    {
      session.descriptor.recv.ring().tail.store(
        unsafe { *session.recv.tail_release.get() },
        Ordering::Release,
      );
      unsafe { SetEvent(session.recv_tail_moved.0) };
      if session
        .descriptor
        .recv
        .ring()
        .alertable
        .load(Ordering::Acquire)
        != 0
      {
        unsafe { SetEvent(session.descriptor.recv.tail_moved.0) };
      }
    }
    guard.leave();
  }
}
