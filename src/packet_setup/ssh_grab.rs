use std::net::Ipv4Addr;
use std::rc::Rc;

use bstr::ByteSlice;
use io_uring::{cqueue, opcode, squeue, types::Fd, Probe};
use nix::{
    errno::Errno,
    libc,
    sys::socket::{socket, AddressFamily, SockFlag, SockType, SockaddrLike},
    unistd,
};

use crate::cmdline_opts::SshVersionScanOptions;
use crate::ring_buffer::{RingBufferDirection, RingBufferInfo, RingEntryInfo, RingBufferAllocator};
use crate::packet_setup::{is_operation_supported, PushError, RawFd, PacketSetup, SockaddrIn, Timeouts};

pub struct SSHScanInstance {
    opts: SshVersionScanOptions,
}

/// Describes what scan step does an entry do
#[derive(Debug)]
enum EntryStep {
    Connect = 0,
    ConnectTimeout,
    Recv,
    RecvTimeout,
    Close,
}

impl From<u8> for EntryStep {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Connect,
            1 => Self::ConnectTimeout,
            2 => Self::Recv,
            3 => Self::RecvTimeout,
            4 => Self::Close,
            _ => unreachable!(),
        }
    }
}

impl SSHScanInstance {
    /// Parse response and log match
    fn handle_response(&self, addr: &SockaddrIn, buf: &[u8]) {
        if self.opts.regex.as_ref().map_or(true, |r| r.is_match(buf)) {
            println!("{} {:?}", Ipv4Addr::from(addr.ip()), buf.as_bstr());
        }
    }

    pub fn new(opts: &SshVersionScanOptions) -> Self {
        Self {
            opts: opts.to_owned(),
        }
    }
}

impl PacketSetup for SSHScanInstance {
    fn is_supported(&self, probe: &Probe) {
        is_operation_supported(probe, opcode::Connect::CODE, "connect");
        is_operation_supported(probe, opcode::LinkTimeout::CODE, "link timeout");
        is_operation_supported(probe, opcode::ReadFixed::CODE, "read fixed");
        is_operation_supported(probe, opcode::Close::CODE, "close");
    }

    fn max_out_size(&mut self) -> Option<usize> {
        None
    }

    fn operation_per_address(&self) -> usize {
        5
    }

    fn process_completed_entry(
        &self,
        cq_entry: &cqueue::Entry,
        entry_info: &RingEntryInfo,
        ring_allocator: &RingBufferAllocator,
    ) -> bool {
        let step = EntryStep::from(entry_info.step);
        let errno = Errno::from_i32(-cq_entry.result());
        log::debug!(
            "op #{} ({:?} {}) returned {} ({:?})",
            cq_entry.user_data(),
            step,
            entry_info.address,
            cq_entry.result(),
            errno
        );
        if let Some(buf) = entry_info.buffer.as_ref() {
            log::debug!(
                "buf: {:?}",
                String::from_utf8_lossy(ring_allocator.get_buf(buf.rbidx))
            );
        }
        match step {
            EntryStep::Recv => {
                let ret = cq_entry.result();
                if ret > 0 {
                    let buf = ring_allocator.get_buf(entry_info.buffer.as_ref().unwrap().rbidx);
                    self.handle_response(&entry_info.address, &buf[..ret as usize]);
                }
                false
            }
            EntryStep::Close => {
                if cq_entry.result() == -libc::ECANCELED {
                    // if a previous entry errored and the socket close was canceled, do it now to avoid fd leak
                    unistd::close(entry_info.file_desc).unwrap();
                }
                true
            }
            _ => false,
        }
    }

    fn push_scan_operation(
        &mut self,
        sckt: RawFd,
        addr: &SockaddrIn,
        squeue: &mut io_uring::squeue::SubmissionQueue,
        allocator: &mut RingBufferAllocator,
        timeouts: &Timeouts,
    ) -> Result<usize, PushError> {
        let addr = Rc::new(addr.to_owned());

        let entry_connect_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: EntryStep::Connect as u8,
                buffer: None,
                file_desc: sckt,
            })
            .unwrap();
        let op_connect = opcode::Connect::new(Fd(sckt), addr.as_ptr(), addr.len())
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_connect_idx);

        let entry_connect_timeout_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: EntryStep::ConnectTimeout as u8,
                buffer: None,
                file_desc: sckt,
            })
            .unwrap();
        let op_connect_timeout = opcode::LinkTimeout::new(&timeouts.connect)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_connect_timeout_idx);

        let rx_buffer = allocator.alloc_buf(RingBufferDirection::RXIn, None);
        let op_recv_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: EntryStep::Recv as u8,
                buffer: Some(RingBufferInfo {
                    rbidx: rx_buffer.rbidx,
                    direction: RingBufferDirection::RXIn,
                }),
                file_desc: sckt,
            })
            .unwrap();
        let op_recv = opcode::ReadFixed::new(
            Fd(sckt),
            rx_buffer.rwvector.iov_base.cast::<u8>(),
            rx_buffer.rwvector.iov_len as u32,
            rx_buffer.rbidx as u16,
        )
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(op_recv_idx);

        let entry_recv_timeout_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: EntryStep::RecvTimeout as u8,
                buffer: None,
                file_desc: sckt,
            })
            .unwrap();
        let op_recv_timeout = opcode::LinkTimeout::new(&timeouts.read)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_recv_timeout_idx);

        let entry_close_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: EntryStep::Close as u8,
                buffer: None,
                file_desc: sckt,
            })
            .unwrap();
        let op_close = opcode::Close::new(Fd(sckt))
            .build()
            .user_data(entry_close_idx);

        let ops = [
            op_connect,
            op_connect_timeout,
            op_recv,
            op_recv_timeout,
            op_close,
        ];
        unsafe {
            squeue.push_multiple(&ops).expect("Failed to push ops");
        }
        Ok(ops.len())
    }

    fn socket(&self) -> RawFd {
        socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
            .expect("Failed to create TCP socket")
    }
}