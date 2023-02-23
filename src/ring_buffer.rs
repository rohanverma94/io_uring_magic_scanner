use std::ffi::c_void;
use std::os::unix::io::RawFd;
use std::rc::Rc;

use io_uring::Submitter;
pub use nix::libc::iovec;
use nix::sys::socket::SockaddrIn;

pub type RingEntryIdx = u64;

#[derive(Clone)]
pub struct RingEntryInfo {
    pub address: Rc<SockaddrIn>,
    pub step: u8,
    pub buffer: Option<RingBufferInfo>,
    pub file_desc: RawFd,
}

pub type RingBufferIdx = usize;

pub struct RingBuffer {
    pub rbidx: RingBufferIdx,
    pub rwvector: iovec, // Read Write Vector, get the length via iov_len
}

#[derive(Clone)]
pub struct RingBufferInfo {
    pub rbidx: RingBufferIdx,
    pub direction: RingBufferDirection,
}

#[derive(Clone, Debug)]
pub enum RingBufferDirection {
    RXIn,
    TXOut,
}

pub struct RingBufferAllocator {
    buffer_list: Vec<Vec<u8>>,
    rx_buffer_size: usize,
    tx_buffer_size: Option<usize>,
    entry_list: Vec<Option<RingEntryInfo>>,
    available_entry_idx: Vec<RingEntryIdx>,
    available_rx_buffer_idx: Vec<RingBufferIdx>,
    available_tx_buffer_idx: Vec<RingBufferIdx>,
}

impl RingBufferAllocator {
    pub fn allocate_ring(
        initial_size: usize,
        rx_buffer_size: usize,
        tx_buffer_size: Option<usize>,
        submitter: &Submitter,
    ) -> Self {
        let mut buffers = Vec::with_capacity(
        initial_size * 2);
        buffers.append(&mut vec![vec![0; rx_buffer_size];
        initial_size]);
        if let Some(tx_buffer_size) = tx_buffer_size {
            buffers.append(&mut vec![vec![0; tx_buffer_size];
        initial_size]);
        }
        let rwvs: Vec<iovec> = buffers
            .iter_mut()
            .enumerate()
            .map(|(i, b)| iovec {
                iov_base: b.as_mut_ptr() as *mut c_void,
                iov_len: if i <
        initial_size {
                    rx_buffer_size
                } else if let Some(tx_buffer_size) = tx_buffer_size {
                    tx_buffer_size
                } else {
                    unreachable!()
                },
            })
            .collect();
        submitter
            .register_buffers(&rwvs)
            .expect("Failed to register buffers");

        Self {
            buffer_list: buffers,
            rx_buffer_size,
            tx_buffer_size,
            entry_list: vec![None;
        initial_size],
            available_entry_idx: (0..
        initial_size as RingEntryIdx).collect(),
            available_rx_buffer_idx: (0..
        initial_size).collect(),
            available_tx_buffer_idx: (
        initial_size..
        initial_size * 2).collect(),
        }
    }

    pub fn fetch_entry(&self, idx: RingEntryIdx) -> &RingEntryInfo {
        self.entry_list[idx as usize]
            .as_ref()
            .expect("Unallocated entry")
    }

    pub fn has_available_entry_count(&self, count: usize) -> bool {
        self.available_entry_idx.len() >= count
    }

    pub fn allocated_entry_count(&self) -> usize {
        self.entry_list.capacity() - self.available_entry_idx.len()
    }

    pub fn release_entry(&mut self, idx: RingEntryIdx) {
        if let Some(buf) = &self.entry_list[idx as usize].as_ref().unwrap().buffer {
            let buf = buf.clone();
            self.free_buf(&buf.direction, buf.rbidx);
        }
        log::trace!("Freeing entry #{idx}");
        self.available_entry_idx.push(idx);
        self.entry_list[idx as usize] = None;
    }

    pub fn allocate_entry(&mut self, info: RingEntryInfo) -> Option<RingEntryIdx> {
        match self.available_entry_idx.pop() {
            Some(idx) => {
                log::trace!("Allocating entry #{idx}");
                debug_assert!(self.entry_list[idx as usize].is_none());
                self.entry_list[idx as usize] = Some(info);
                Some(idx)
            }
            None => {
                log::trace!("No free entry");
                None
            }
        }
    }

    pub fn get_buf(&self, idx: RingBufferIdx) -> &Vec<u8> {
        &self.buffer_list[idx]
    }

    pub fn free_buf(&mut self, direction: &RingBufferDirection, idx: RingBufferIdx) {
        log::trace!("Freeing {direction:?} buf #{idx}");
        match direction {
            RingBufferDirection::RXIn => &mut self.available_rx_buffer_idx,
            RingBufferDirection::TXOut => &mut self.available_tx_buffer_idx,
        }
            .push(idx)
    }

    pub fn alloc_buf(&mut self, direction: RingBufferDirection, init_val: Option<&[u8]>) -> RingBuffer {
        let idx = match direction {
            RingBufferDirection::RXIn => &mut self.available_rx_buffer_idx,
            RingBufferDirection::TXOut => &mut self.available_tx_buffer_idx,
        }
            .pop()
            .expect("No free buffers");

        let iov = iovec {
            iov_base: self.buffer_list[idx].as_mut_ptr().cast::<c_void>(),
            iov_len: match direction {
                RingBufferDirection::RXIn => self.rx_buffer_size,
                RingBufferDirection::TXOut => self.tx_buffer_size.expect("TX buffer size was not set"),
            },
        };

        log::trace!("Allocating {direction:?} buf #{idx}: {iov:?}");

        if let Some(init_val) = init_val {
            self.buffer_list[idx][..init_val.len()].copy_from_slice(init_val);
        }

        RingBuffer { rbidx: idx, rwvector: iov }
    }
}