use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Result, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use log::{debug, error};

use crate::common::enums::{LinkType, TapType};

use super::{
    format_time, Packet, PCAP_MAGIC, RECORD_HEADER_LEN, SNAP_LEN, VERSION_MAJOR, VERSION_MINOR,
};

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct WriterCounter {
    pub written_count: u64,
    pub written_bytes: u64,
}

#[derive(Debug)]
pub struct Writer {
    pub temp_filename: PathBuf,
    pub counter: WriterCounter,
    writer: BufWriter<File>,
    pub tap_type: TapType,
    pub dispatcher_id: u32,
    pub acl_gid: u16,
    pub vtap_id: u16,
    pub first_pkt_time: Duration,
    pub last_pkt_time: Duration,
}

impl Writer {
    pub fn new<P: AsRef<Path>>(
        base_directory: P,
        buffer_size: usize,
        tap_type: TapType,
        dispatcher_id: u32,
        acl_gid: u16,
        vtap_id: u16,
        pkt_timestamp: Duration,
    ) -> Result<Self> {
        let mut filename = base_directory.as_ref().to_path_buf();
        filename.push(format!("{}", acl_gid));

        if !filename.exists() {
            fs::create_dir_all(filename.as_path())
                .unwrap_or_else(|e| error!("failed to create dir {}: {:?}", filename.display(), e));
        }

        filename.push(format!(
            "{}_{:012x}_0_{}_.{}.pcap.temp",
            tap_type,
            dispatcher_id,
            format_time(pkt_timestamp),
            vtap_id
        ));

        debug!("begin to write packets to {}", filename.display());

        let fp = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(filename.as_path())?;
        let writer = if fp.metadata()?.len() != 0 {
            if buffer_size == 0 {
                BufWriter::new(fp)
            } else {
                BufWriter::with_capacity(buffer_size, fp)
            }
        } else {
            let mut writer = if buffer_size == 0 {
                BufWriter::new(fp)
            } else {
                BufWriter::with_capacity(buffer_size, fp)
            };
            Self::write_global_header(&mut writer, SNAP_LEN)?;
            writer
        };

        Ok(Self {
            temp_filename: filename,
            writer,
            counter: WriterCounter::default(),
            tap_type,
            dispatcher_id,
            acl_gid,
            vtap_id,
            first_pkt_time: pkt_timestamp,
            last_pkt_time: pkt_timestamp,
        })
    }

    fn write_global_header(writer: &mut BufWriter<File>, snap_len: u32) -> Result<()> {
        writer.write(PCAP_MAGIC.to_le_bytes().as_slice())?;
        writer.write(VERSION_MAJOR.to_le_bytes().as_slice())?;
        writer.write(VERSION_MINOR.to_le_bytes().as_slice())?;
        writer.write(snap_len.to_le_bytes().as_slice())?;
        writer.write(u8::from(LinkType::Ethernet).to_le_bytes().as_slice())?;

        Ok(())
    }

    fn write_record_header(
        writer: &mut BufWriter<File>,
        ts: Duration,
        raw_pkt_len: u16,
        pkt_len: u16,
    ) -> Result<()> {
        writer.write((ts.as_secs() as u32).to_le_bytes().as_slice())?;
        writer.write((ts.subsec_micros() as u32).to_le_bytes().as_slice())?;
        writer.write(raw_pkt_len.to_le_bytes().as_slice())?;
        writer.write(pkt_len.to_le_bytes().as_slice())?;
        Ok(())
    }

    pub fn write(&mut self, pkt: Packet) -> Result<()> {
        let pkt_bytes = pkt.bytes();
        Self::write_record_header(
            &mut self.writer,
            pkt.timestamp(),
            pkt_bytes.len() as u16,
            pkt.pkt_len(),
        )?;
        self.writer.write_all(pkt_bytes)?;

        self.counter.written_count += 1;
        self.counter.written_bytes += (RECORD_HEADER_LEN + pkt_bytes.len()) as u64;
        self.last_pkt_time = pkt.timestamp;

        Ok(())
    }

    fn reset_stats(&mut self) {
        self.counter = WriterCounter::default();
    }

    fn get_stats(&self) -> WriterCounter {
        self.counter
    }

    pub fn get_and_reset_stats(&mut self) -> WriterCounter {
        let c = self.get_stats();
        self.reset_stats();
        c
    }
}
