use chrono::offset::Local;
use chrono::DateTime;
use std::io::Write;
use std::time::SystemTime;
use wtun::*;

fn logger(level: LogLevel, timestamp: SystemTime, message: core::fmt::Arguments) {
  let timestamp: DateTime<Local> = timestamp.into();
  eprintln!(
    "[{:?}] [{}] {}",
    level,
    timestamp.format("%d.%m.%Y %T"),
    message
  );
}
fn
ipchecksum(buffer: &[u8]) -> u16
{
    let mut sum: u32 = 0;
    let mut len: u32 = buffer.len() as u32;
    let mut i = 0;
    while len > 1 {
      sum += u16::from_ne_bytes(buffer[i..i+2].try_into().unwrap()) as u32;
      len -= 2;
      i += 2;
    }
    if len != 0 {
      sum += buffer[i] as u32;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return !sum as u16;
}
fn make_icmp<'a, 'p>(mut packet: SendPacketWrite<'a, 'p>)
{
  let mut buf = [0u8; 28];
  // Packet[0] = 0x45;
  buf[0] = 0x45;
  // *(USHORT *)&Packet[2] = htons(28);
  buf[2..4].copy_from_slice(&28u16.to_be_bytes());
  // Packet[8] = 255;
  // Packet[9] = 1;
  buf[8..10].copy_from_slice(&[255, 1]);
  // *(ULONG *)&Packet[12] = htonl((10 << 24) | (6 << 16) | (7 << 8) | (8 << 0)); /* 10.6.7.8 */
  buf[12..16].copy_from_slice(&((10u32 << 24) | (6u32 << 16) | (7u32 << 8) | (8u32 << 0)).to_be_bytes());
  // *(ULONG *)&Packet[16] = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
  buf[16..20].copy_from_slice(&((10u32 << 24) | (6u32 << 16) | (7u32 << 8) | (7u32 << 0)).to_be_bytes());
  // *(USHORT *)&Packet[10] = IPChecksum(Packet, 20);
  let check_sum = &(ipchecksum(&buf[0..20])).to_ne_bytes();
  buf[10..12].copy_from_slice(check_sum);
  // Packet[20] = 8;
  buf[20] = 8;
  // *(USHORT *)&Packet[22] = IPChecksum(&Packet[20], 8);
  let check_sum = &(ipchecksum(&buf[20..28])).to_ne_bytes();
  buf[22..24].copy_from_slice(check_sum);
  packet.write_all(&buf).unwrap();
  // Log(WINTUN_LOG_INFO, L"Sending IPv4 ICMP echo request to 10.6.7.8 from 10.6.7.7");
  eprintln!("[INFO] Sending IPv4 ICMP echo request to 10.6.7.8 from 10.6.7.7");
}

#[test]
fn creates_session() {
  set_logger(logger);
  let mut adapter = Adapter::create("test", "test type", None).unwrap();
  let _session = adapter.start_session(ring_capacity!(MAX_RING_CAPACITY)).unwrap();
}
#[test]
fn creates_and_sends() {
  set_logger(logger);
  let mut adapter = Adapter::create("test", "test type", None).unwrap();
  let session = adapter.start_session(ring_capacity!(MAX_RING_CAPACITY)).unwrap();
  let mut packet = session.allocate(packet_size!(28)).unwrap();
  let packet_write = packet.write();
  make_icmp(packet_write);
  packet.send();
}
#[test]
fn creates_and_recvs() {
  set_logger(logger);
  let mut adapter = Adapter::create("test", "test type", None).unwrap();
  let session = adapter.start_session(ring_capacity!(MAX_RING_CAPACITY)).unwrap();
  session.block_until_read_avaliable(None).unwrap();
  let packet = session.recv().unwrap();
  println!("{packet:#?}");
}


#[test]
fn creates_and_sends_alerts() {
  set_logger(logger);
  let mut adapter = Adapter::create("test", "test type", None).unwrap();
  let session = adapter.start_session(ring_capacity!(MIN_RING_CAPACITY)).unwrap();
  assert_eq!(session.is_write_avaliable().unwrap(), true);
  for _ in 0.. {
    while session.is_write_avaliable().unwrap() {}
    let mut packet = match session.allocate(packet_size!(MAX_IP_PACKET_SIZE)) {
      Ok(packet) => packet,
      Err(err) if err == IoError::Exhausted => {
        break;
      },
      err => err.unwrap(),
    };
    let packet_write = packet.write();
    make_icmp(packet_write);
    packet.send();
  }
  assert_ne!(session.is_write_avaliable().unwrap(), true);
}