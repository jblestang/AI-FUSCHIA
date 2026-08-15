//! TAP device I/O for attaching netstack3 to a Linux L2 bridge.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::libc::{self, c_char, ifreq, IFNAMSIZ, IFF_NO_PI, IFF_TAP, TUNSETIFF};

pub struct TapDevice {
    inner: std::fs::File,
    read_buf: Vec<u8>,
}

impl TapDevice {
    pub fn attach(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= IFNAMSIZ as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tap name must be non-empty and shorter than IFNAMSIZ",
            ));
        }

        let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
        let fd = file.as_raw_fd();

        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        let name_c = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tap name"))?;
        let name_bytes = name_c.as_bytes_with_nul();
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const c_char,
                ifr.ifr_name.as_mut_ptr(),
                name_bytes.len(),
            );
        }
        ifr.ifr_ifru.ifru_flags = (IFF_TAP | IFF_NO_PI) as libc::c_short;

        if unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut ifreq) } < 0 {
            return Err(io::Error::last_os_error());
        }

        fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;

        Ok(Self { inner: file, read_buf: vec![0u8; 65536] })
    }

    pub fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.inner.read(&mut self.read_buf) {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(self.read_buf[..n].to_vec())),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.inner.write_all(frame)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}
