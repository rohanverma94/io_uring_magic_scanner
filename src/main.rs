#![feature(byte_slice_trim_ascii)]

use std::cmp::min;
use std::fmt::Write;
use std::io;
use std::net::SocketAddrV4;
use std::os::unix::io::{AsRawFd};
use std::time::Duration;

use indicatif::{HumanDuration, ProgressBar, ProgressState, ProgressStyle};
use io_uring::types::Timespec;
use io_uring::{IoUring, Probe};
use iprange::IpRange;
use nix::sys::{resource, socket::SockaddrIn};
use structopt::StructOpt;

use packet_setup::http_grab::HttpScanInstance;
use packet_setup::ssh_grab::SSHScanInstance;
use packet_setup::tcp_grab::TCPScanInstance;
use packet_setup::{is_pushable, PacketSetup};

mod cmdline_opts;
mod ring_buffer;
mod packet_setup;

fn main() -> io::Result<()> {
    // Spawn a Simplelogger instance
    simple_logger::SimpleLogger::new()
        .init()
        .expect("Failed to init logger");

    // Parse command line args
    let cl_opts = cmdline_opts::CommandLineOptions::from_args();
    log::trace!("{:?}", cl_opts);

    // Bump limit of open files
    let (soft_limit, hard_limit) = resource::getrlimit(resource::Resource::RLIMIT_NOFILE).unwrap();
    resource::setrlimit(resource::Resource::RLIMIT_NOFILE, hard_limit, hard_limit).unwrap();
    log::info!("Bumped RLIMIT_NOFILE from {soft_limit} to {hard_limit}");

    let mut iorings = IoUring::new(cl_opts.ring_size as u32)?;

    let mut scan: Box<dyn PacketSetup> = match &cl_opts.scan_opts {
        cmdline_opts::ScanOptions::HttpHeaderMatch(scan_opts) => {
            Box::new(HttpScanInstance::new(scan_opts))
        }
        cmdline_opts::ScanOptions::SshVersion(scan_opts) => Box::new(SSHScanInstance::new(scan_opts)),
        cmdline_opts::ScanOptions::TcpConnect(_) => Box::new(TCPScanInstance::new()),
    };

    // Probe
    let mut probe = Probe::new();
    iorings.submitter().register_probe(&mut probe)?;
    scan.is_supported(&probe);

    // Init map to track ring state
    let mut ring_allocator = ring_buffer::RingBufferAllocator::allocate_ring(
        cl_opts.ring_size,
        cl_opts.max_read_size,
        scan.max_out_size(),
        &iorings.submitter(),
    );

    let ip_ranges = cl_opts.ip_subnets.iter().copied().collect::<IpRange<_>>();
    let total_ip_count: usize = ip_ranges.iter().map(|r| r.hosts().count()).sum();
    let mut ip_iter = ip_ranges.iter().flat_map(|r| r.hosts());

    let progress = ProgressBar::new(total_ip_count as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "Scanning IPs {msg} {wide_bar} {pos}/{len} ({smoothed_per_sec}) ETA {smoothed_eta}",
            )
            .unwrap()
            .with_key(
                "smoothed_eta",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.len()) {
                    (pos, Some(len)) => write!(
                        w,
                        "{:#}",
                        HumanDuration(Duration::from_millis(
                            (s.elapsed().as_millis() * (len as u128 - pos as u128) / (pos as u128))
                                as u64
                        ))
                    )
                        .unwrap(),
                    _ => write!(w, "-").unwrap(),
                },
            )
            .with_key(
                "smoothed_per_sec",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.elapsed().as_millis()) {
                    (pos, elapsed_ms) if elapsed_ms > 0 => {
                        write!(w, "{:.2}/s", pos as f64 * 1000_f64 / elapsed_ms as f64).unwrap()
                    }
                    _ => write!(w, "-").unwrap(),
                },
            ),
    );

    // Build timeouts for direct use by io_uring
    let timeouts = packet_setup::Timeouts {
        connect: Timespec::new().sec(cl_opts.timeout_connect_secs),
        read: Timespec::new().sec(cl_opts.timeout_read_secs),
        write: Timespec::new().sec(cl_opts.timeout_write_secs),
    };

    let mut done = false;
    while !done {
        while is_pushable(&iorings.submission(), &*scan, &ring_allocator) {
            if let Some(ip_addr) = ip_iter.next() {
                let addr = SockaddrIn::from(SocketAddrV4::new(ip_addr, cl_opts.port));
                let sckt = scan.socket();
                log::trace!("New socket: {}", sckt);

                scan.push_scan_operation(
                    sckt.as_raw_fd(),
                    &addr,
                    &mut iorings.submission(),
                    &mut ring_allocator,
                    &timeouts,
                )
                    .expect("Failed to push ring ops");
            } else if ring_allocator.allocated_entry_count() == 0 {
                done = true;
                break;
            } else {
                break;
            }
        }

        let completed_count = iorings.completion().len();
        log::trace!("Completed count before wait: {completed_count}");
        iorings.submit_and_wait(min(
            cl_opts.ring_batch_size,
            ring_allocator.allocated_entry_count() - completed_count,
        ))?;
        log::trace!("Completed count after wait: {}", iorings.completion().len());

        for ce in iorings.completion() {
            let entry = ring_allocator.fetch_entry(ce.user_data());
            if scan.process_completed_entry(&ce, entry, &ring_allocator) {
                progress.inc(1);
            }
            ring_allocator.release_entry(ce.user_data());
        }
    }
    progress.finish();

    Ok(())
}