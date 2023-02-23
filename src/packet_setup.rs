use std::os::unix::io::RawFd;

use io_uring::{
    cqueue,
    squeue::{PushError, SubmissionQueue},
    types::Timespec,
    Probe,
};
use nix::sys::socket::SockaddrIn;

use crate::ring_buffer::{RingEntryInfo, RingBufferAllocator};

pub mod http_grab;
pub mod ssh_grab;
pub mod tcp_grab;

pub struct Timeouts {
    pub connect: Timespec,
    pub read: Timespec,
    pub write: Timespec,
}

/// Network scan
pub trait PacketSetup {
    /// Check if this scan is supported in the kernel's io_uring code and panic if not
    fn is_supported(&self, probe: &Probe);

    /// Maximum number of bytes that should be sent (used to preallocate buffers)
    fn max_out_size(&mut self) -> Option<usize>;

    /// Number of io_uring operations required to scan one IP address
    fn operation_per_address(&self) -> usize;

    /// Process a completed entry and return true if this is the IP's last entry
    fn process_completed_entry(
        &self,
        cqueue_entry: &cqueue::Entry,
        entry_info: &RingEntryInfo,
        ringbuffer_allocator: &RingBufferAllocator,
    ) -> bool;

    /// Push ring-buffer operations to scan peer IP
    fn push_scan_operation(
        &mut self,
        socket: RawFd,
        address: &SockaddrIn,
        submit_queue: &mut SubmissionQueue,
        allocator: &mut RingBufferAllocator,
        timeouts: &Timeouts,
    ) -> Result<usize, PushError>;

    /// Init a socket for this scan
    fn socket(&self) -> RawFd;
}

fn is_operation_supported(probe: &Probe, opcode: u8, name: &str) {
    assert!(
        probe.is_supported(opcode),
        "This kernel does not support io_uring op code {} ({:?})",
        name,
        opcode
    );
}

pub fn is_pushable(submit_queue: &SubmissionQueue, packet_setup: &dyn PacketSetup, ringbuffer_allocator: &RingBufferAllocator) -> bool {
    let operation_per_address = packet_setup.operation_per_address();
    ringbuffer_allocator.has_available_entry_count(operation_per_address) && (submit_queue.capacity() - submit_queue.len() >= operation_per_address)
}