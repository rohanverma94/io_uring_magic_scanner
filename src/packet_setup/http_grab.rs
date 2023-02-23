use std::fmt::Write;
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

use crate::cmdline_opts::HttpHeaderMatchScanOptions;
use crate::ring_buffer::{RingBufferDirection, RingBufferInfo, RingEntryInfo, RingBufferAllocator};
use crate::packet_setup::{is_operation_supported, PushError, RawFd, PacketSetup, SockaddrIn, Timeouts};

pub struct HttpScanInstance {
    opts: HttpHeaderMatchScanOptions,
    tx_buf_size: Option<usize>,
}

/// Describes what scan step does an entry do
#[derive(Debug)]
enum HttpStatus {
    Connect = 0,
    ConnectTimeout,
    Send,
    SendTimeout,
    Recv,
    RecvTimeout,
    Close,
}

impl From<u8> for HttpStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Connect,
            1 => Self::ConnectTimeout,
            2 => Self::Send,
            3 => Self::SendTimeout,
            4 => Self::Recv,
            5 => Self::RecvTimeout,
            6 => Self::Close,
            _ => unreachable!(),
        }
    }
}

impl HttpScanInstance {
    /// Parse response headers and log match
    fn handle_response(&self, addr: &SockaddrIn, buf: &[u8]) {
        // The parsing here never copies data from the response buffer
        // We also usr bstr to operate directly on &[u8] instead of &str which would require valid UTF-8
        // See https://www.rfc-editor.org/rfc/rfc2616.html#section-4.2
        let mut match_count = 0;
        for line in buf.lines() {
            if line.is_empty() {
                // double crlf, end of headers, bail out
                break;
            }
            if let Some((hdr_key, hdr_value)) = Self::parse_header_line(line) {
                for rule in self
                    .opts
                    .response_header_regexs
                    .iter()
                    .filter(|r| r.key.as_bytes() == hdr_key)
                {
                    if rule.val_regex.is_match(hdr_value) {
                        match_count += 1;
                    }
                }
            }
        }
        if match_count == self.opts.response_header_regexs.len() {
            println!("{}", Ipv4Addr::from(addr.ip()));
        }
    }

    pub fn new(opts: &HttpHeaderMatchScanOptions) -> Self {
        Self {
            opts: opts.to_owned(),
            tx_buf_size: None,
        }
    }

    fn parse_header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
        if let Some((key, value)) = line.split_once_str(":") {
            let key = key.trim_ascii_end();
            let value = value.trim_ascii_start();
            Some((key, value))
        } else {
            None
        }
    }

    fn format_request(&self, addr: &SockaddrIn) -> String {
        let mut s = if let Some(size_hint) = self.tx_buf_size {
            String::with_capacity(size_hint)
        } else {
            String::new()
        };
        write!(
            &mut s,
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            self.opts.request_verb, self.opts.request_uri, addr,
        )
            .unwrap();
        for hdr in &self.opts.request_headers {
            write!(&mut s, "{}: {}\r\n", hdr.key, hdr.val).unwrap();
        }
        write!(&mut s, "\r\n").unwrap();
        s
    }
}

impl PacketSetup for HttpScanInstance {
    fn is_supported(&self, probe: &Probe) {
        is_operation_supported(probe, opcode::Connect::CODE, "connect");
        is_operation_supported(probe, opcode::LinkTimeout::CODE, "link timeout");
        is_operation_supported(probe, opcode::WriteFixed::CODE, "write fixed");
        is_operation_supported(probe, opcode::ReadFixed::CODE, "read fixed");
        is_operation_supported(probe, opcode::Close::CODE, "close");
    }

    fn max_out_size(&mut self) -> Option<usize> {
        let sz = self
            .format_request(&SockaddrIn::new(255, 255, 255, 255, u16::MAX))
            .len();
        self.tx_buf_size = Some(sz);
        Some(sz)
    }

    fn operation_per_address(&self) -> usize {
        7
    }

    fn process_completed_entry(
        &self,
        cq_entry: &cqueue::Entry,
        entry_info: &RingEntryInfo,
        ring_allocator: &RingBufferAllocator,
    ) -> bool {
        let step = HttpStatus::from(entry_info.step);
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
            HttpStatus::Recv => {
                if cq_entry.result() > 0 {
                    self.handle_response(
                        &entry_info.address,
                        ring_allocator.get_buf(entry_info.buffer.as_ref().unwrap().rbidx),
                    );
                }
                false
            }
            HttpStatus::Close => {
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
                step: HttpStatus::Connect as u8,
                buffer: None,
                file_desc: sckt,
            })
            .unwrap();
        let op_connect = opcode::Connect::new(Fd(sckt), addr.as_ptr(), addr.len())
            .build()
            .flags(squeue::Flags::IO_LINK | squeue::Flags::ASYNC)
            .user_data(entry_connect_idx);

        let entry_connect_timeout_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: HttpStatus::ConnectTimeout as u8,
                buffer: None,
                file_desc: sckt,
            })
            .unwrap();
        let op_connect_timeout = opcode::LinkTimeout::new(&timeouts.connect)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_connect_timeout_idx);

        let req = self.format_request(&addr);
        let tx_buffer = allocator.alloc_buf(RingBufferDirection::TXOut, Some(req.as_bytes()));
        let op_send_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: HttpStatus::Send as u8,
                buffer: Some(RingBufferInfo {
                    rbidx: tx_buffer.rbidx,
                    direction: RingBufferDirection::TXOut,
                }),
                file_desc: sckt,
            })
            .unwrap();
        let op_send = opcode::WriteFixed::new(
            Fd(sckt),
            tx_buffer.rwvector.iov_base.cast::<u8>(),
            tx_buffer.rwvector.iov_len as u32,
            tx_buffer.rbidx as u16,
        )
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(op_send_idx);

        let entry_send_timeout_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: HttpStatus::SendTimeout as u8,
                buffer: None,
                file_desc: sckt,
            })
            .unwrap();
        let op_send_timeout = opcode::LinkTimeout::new(&timeouts.write)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_send_timeout_idx);

        let rx_buffer = allocator.alloc_buf(RingBufferDirection::RXIn, None);
        let op_recv_idx = allocator
            .allocate_entry(RingEntryInfo {
                address: Rc::clone(&addr),
                step: HttpStatus::Recv as u8,
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
                step: HttpStatus::RecvTimeout as u8,
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
                step: HttpStatus::Close as u8,
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
            op_send,
            op_send_timeout,
            op_recv,
            op_recv_timeout,
            op_close,
        ];
        log::trace!("Pushing: {ops:#?}");
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

#[cfg(test)]
mod tests {
    use super::*;

    use bstr::B;

    #[test]
    fn test_parse_header_line() {
        assert_eq!(HttpScanInstance::parse_header_line(B("200 OK")), None);
        assert_eq!(
            HttpScanInstance::parse_header_line(B("Server: srv 1.2.3")),
            Some((B("Server"), B("srv 1.2.3")))
        );
        assert_eq!(
            HttpScanInstance::parse_header_line(B(" Server: srv 1.2.3")),
            Some((B(" Server"), B("srv 1.2.3")))
        );
        assert_eq!(
            HttpScanInstance::parse_header_line(B("Server:   srv 1.2.3")),
            Some((B("Server"), B("srv 1.2.3")))
        );
        assert_eq!(
            HttpScanInstance::parse_header_line(B("Server: srv 1.2.3  ")),
            Some((B("Server"), B("srv 1.2.3  ")))
        );
        assert_eq!(
            HttpScanInstance::parse_header_line(B("Server:: srv 1.2.3")),
            Some((B("Server"), B(": srv 1.2.3")))
        );
    }
}