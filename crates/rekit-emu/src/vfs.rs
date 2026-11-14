//! A tiny virtual filesystem.
//!
//! Anti-debug and licence checks read files, not only call functions:
//! `/proc/self/status` for `TracerPid`, `/proc/self/maps` for injected
//! libraries, `/dev/urandom` for keys. Those reads are answered here so the
//! guest never sees the host.

use crate::emu::{State, VFile};

pub fn open(st: &mut State, path: &str, writable: bool, create: bool) -> Option<u64> {
    let trimmed = path.trim_end_matches('\0');
    let random = matches!(trimmed, "/dev/urandom" | "/dev/random");
    let data = if st.vfs {
        if random {
            Vec::new()
        } else {
            match fake(trimmed, st) {
                Some(d) => d,
                None if create || writable => Vec::new(),
                None => return None,
            }
        }
    } else if create || writable {
        Vec::new()
    } else {
        return None;
    };
    st.files.push(VFile {
        path: trimmed.to_string(),
        data,
        pos: 0,
        writable,
        random,
    });
    Some((st.files.len() + 2) as u64)
}

pub fn file(st: &mut State, fd: u64) -> Option<&mut VFile> {
    if fd < 3 {
        return None;
    }
    st.files.get_mut((fd - 3) as usize)
}

pub fn read(st: &mut State, fd: u64, count: usize) -> Vec<u8> {
    if fd == 0 {
        // No stdin in this environment: behave like an empty pipe.
        return Vec::new();
    }
    let Some(f) = file(st, fd) else {
        return Vec::new();
    };
    if f.random {
        return st.fill_random(count);
    }
    let start = f.pos.min(f.data.len());
    let end = (start + count).min(f.data.len());
    let out = f.data[start..end].to_vec();
    f.pos = end;
    out
}

pub fn write(st: &mut State, fd: u64, data: &[u8]) -> usize {
    if fd == 1 || fd == 2 {
        st.write_output_bytes(data);
        return data.len();
    }
    let Some(f) = file(st, fd) else {
        return 0;
    };
    if !f.writable {
        return 0;
    }
    let start = f.pos;
    if start + data.len() > f.data.len() {
        f.data.resize(start + data.len(), 0);
    }
    f.data[start..start + data.len()].copy_from_slice(data);
    f.pos = start + data.len();
    data.len()
}

pub fn seek(st: &mut State, fd: u64, off: i64, whence: u32) -> i64 {
    let Some(f) = file(st, fd) else {
        return -1;
    };
    let base = match whence {
        0 => 0,
        1 => f.pos as i64,
        2 => f.data.len() as i64,
        _ => return -1,
    };
    let next = base + off;
    if next < 0 {
        return -1;
    }
    f.pos = next as usize;
    next
}

pub fn close(st: &mut State, fd: u64) {
    if fd >= 3 {
        if let Some(slot) = st.files.get_mut((fd - 3) as usize) {
            slot.data.clear();
            slot.pos = 0;
        }
    }
}

fn fake(path: &str, st: &State) -> Option<Vec<u8>> {
    let text = match path {
        "/proc/self/status" | "/proc/self/task/1/status" => status(),
        "/proc/self/maps" | "/proc/self/task/1/maps" => maps(),
        "/proc/self/cmdline" => "rekit-emu\0".to_string(),
        "/proc/self/comm" | "/proc/self/task/1/comm" => "rekit-emu\n".to_string(),
        "/proc/self/environ" => "PATH=/usr/bin\0HOME=/root\0".to_string(),
        "/proc/self/stat" => {
            "1 (rekit-emu) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
                .to_string()
        }
        "/proc/version" => "Linux version 6.0.0 (rekit) #1 SMP\0".to_string(),
        "/proc/sys/kernel/randomize_va_space" => "0\n".to_string(),
        "/dev/null" => String::new(),
        "/dev/zero" => vec![0u8; 4096].iter().map(|_| '\0').collect(),
        _ => return None,
    };
    let mut bytes = text.into_bytes();
    if path == "/dev/zero" {
        bytes = vec![0u8; 4096];
    }
    // `st` is only used for the address-space picture; keep the parameter so
    // the map can grow richer without changing call sites.
    let _ = st;
    Some(bytes)
}

fn status() -> String {
    let mut out = String::new();
    out.push_str("Name:\trekit-emu\n");
    out.push_str("State:\tR (running)\n");
    out.push_str("Tgid:\t1\n");
    out.push_str("Pid:\t1\n");
    out.push_str("PPid:\t1\n");
    out.push_str("TracerPid:\t0\n");
    out.push_str("Uid:\t1000\t1000\t1000\t1000\n");
    out.push_str("Gid:\t1000\t1000\t1000\t1000\n");
    out.push_str("FDSize:\t8\n");
    out.push_str("VmSize:\t  16384 kB\n");
    out.push_str("VmRSS:\t   4096 kB\n");
    out.push_str("Threads:\t1\n");
    out.push_str("Seccomp:\t0\n");
    out
}

fn maps() -> String {
    let mut out = String::new();
    out.push_str("00400000-00500000 r-xp 00000000 00:00 0      /usr/bin/rekit-emu\n");
    out.push_str("00600000-00601000 r--p 00000000 00:00 0      /usr/bin/rekit-emu\n");
    out.push_str("7ff000000000-7ff000100000 rw-p 00000000 00:00 0 [stack]\n");
    out.push_str("7ff000200000-7ff000300000 r-xp 00000000 00:00 0 [vdso]\n");
    out
}
