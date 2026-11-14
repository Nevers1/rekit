//! Syscall interception.
//!
//! Both the instruction level (`syscall` on x86-64, `int 0x80` on x86,
//! `svc #0` on ARM) and the libc wrappers end up here. Numbers are per
//! architecture, so the dispatcher normalises them into one small enum first.

use crate::emu::{read_bytes, read_cstr, syscall_args, write_bytes, State, Stop, Uc};
use crate::loader::Arch;
use crate::vfs;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sys {
    Read,
    Write,
    Open,
    OpenAt,
    Close,
    Lseek,
    Fstat,
    GetPid,
    GetPpid,
    GetTid,
    GetUid,
    GetEuid,
    GetGid,
    GetEgid,
    Exit,
    ExitGroup,
    ClockGettime,
    Gettimeofday,
    Time,
    Ptrace,
    Getrandom,
    Brk,
    Mmap,
    Munmap,
    Mprotect,
    ArchPrctl,
    Futex,
    Uname,
    Access,
    Readlink,
    Other,
}

fn classify(arch: Arch, nr: u64) -> Sys {
    match arch {
        Arch::X86_64 => match nr {
            0 => Sys::Read,
            1 => Sys::Write,
            2 => Sys::Open,
            3 => Sys::Close,
            8 => Sys::Lseek,
            5 | 4 => Sys::Fstat,
            9 => Sys::Mmap,
            10 => Sys::Mprotect,
            11 => Sys::Munmap,
            12 => Sys::Brk,
            39 => Sys::GetPid,
            60 => Sys::Exit,
            102 => Sys::GetUid,
            104 => Sys::GetGid,
            107 => Sys::GetEuid,
            108 => Sys::GetEgid,
            110 => Sys::GetPpid,
            186 => Sys::GetTid,
            201 => Sys::Time,
            202 => Sys::Futex,
            228 => Sys::ClockGettime,
            96 => Sys::Gettimeofday,
            257 => Sys::OpenAt,
            318 => Sys::Getrandom,
            231 => Sys::ExitGroup,
            101 => Sys::Ptrace,
            158 => Sys::ArchPrctl,
            63 => Sys::Uname,
            21 => Sys::Access,
            89 => Sys::Readlink,
            _ => Sys::Other,
        },
        Arch::X86 => match nr {
            3 => Sys::Read,
            4 => Sys::Write,
            5 => Sys::Open,
            6 => Sys::Close,
            19 => Sys::Lseek,
            108 => Sys::Fstat,
            90 => Sys::Mmap,
            91 => Sys::Munmap,
            125 => Sys::Mprotect,
            45 => Sys::Brk,
            20 => Sys::GetPid,
            1 => Sys::Exit,
            64 => Sys::GetPpid,
            199 => Sys::GetUid,
            200 => Sys::GetGid,
            201 => Sys::GetEuid,
            202 => Sys::GetEgid,
            224 => Sys::GetTid,
            13 => Sys::Time,
            78 => Sys::Gettimeofday,
            265 => Sys::ClockGettime,
            26 => Sys::Ptrace,
            355 => Sys::Getrandom,
            252 => Sys::ExitGroup,
            295 => Sys::OpenAt,
            122 => Sys::Uname,
            33 => Sys::Access,
            85 => Sys::Readlink,
            _ => Sys::Other,
        },
        Arch::Arm => match nr {
            3 => Sys::Read,
            4 => Sys::Write,
            5 => Sys::Open,
            6 => Sys::Close,
            19 => Sys::Lseek,
            108 => Sys::Fstat,
            192 => Sys::Mmap,
            91 => Sys::Munmap,
            125 => Sys::Mprotect,
            45 => Sys::Brk,
            20 => Sys::GetPid,
            1 => Sys::Exit,
            64 => Sys::GetPpid,
            199 => Sys::GetUid,
            200 => Sys::GetGid,
            201 => Sys::GetEuid,
            202 => Sys::GetEgid,
            224 => Sys::GetTid,
            13 => Sys::Time,
            78 => Sys::Gettimeofday,
            263 => Sys::ClockGettime,
            26 => Sys::Ptrace,
            384 => Sys::Getrandom,
            248 => Sys::ExitGroup,
            322 => Sys::OpenAt,
            122 => Sys::Uname,
            33 => Sys::Access,
            85 => Sys::Readlink,
            _ => Sys::Other,
        },
        Arch::Arm64 => match nr {
            63 => Sys::Read,
            64 => Sys::Write,
            56 => Sys::OpenAt,
            57 => Sys::Close,
            62 => Sys::Lseek,
            80 => Sys::Fstat,
            222 => Sys::Mmap,
            215 => Sys::Munmap,
            226 => Sys::Mprotect,
            214 => Sys::Brk,
            172 => Sys::GetPid,
            93 => Sys::Exit,
            94 => Sys::ExitGroup,
            173 => Sys::GetPpid,
            174 => Sys::GetUid,
            176 => Sys::GetGid,
            175 => Sys::GetEuid,
            177 => Sys::GetEgid,
            178 => Sys::GetTid,
            169 => Sys::Gettimeofday,
            113 => Sys::ClockGettime,
            101 => Sys::Ptrace,
            278 => Sys::Getrandom,
            48 => Sys::Access,
            78 => Sys::Readlink,
            160 => Sys::Uname,
            _ => Sys::Other,
        },
    }
}

/// `int 0x80` on x86 (and on x86-64, where it uses the 32-bit table).
pub fn interrupt(uc: &mut Uc<'_>, st: &mut State, arch: Arch, intno: u32) -> bool {
    let (nr, args) = match arch {
        Arch::X86 => {
            if intno != 0x80 {
                return false;
            }
            (
                uc.reg_read(unicorn_engine::RegisterX86::EAX as i32)
                    .unwrap_or(0),
                syscall_args(uc, Arch::X86),
            )
        }
        Arch::X86_64 => {
            if intno != 0x80 {
                return false;
            }
            (
                uc.reg_read(unicorn_engine::RegisterX86::EAX as i32)
                    .unwrap_or(0),
                syscall_args(uc, Arch::X86),
            )
        }
        Arch::Arm => {
            (
                uc.reg_read(unicorn_engine::RegisterARM::R7 as i32)
                    .unwrap_or(0),
                syscall_args(uc, Arch::Arm),
            )
        }
        Arch::Arm64 => {
            (
                uc.reg_read(unicorn_engine::RegisterARM64::X8 as i32)
                    .unwrap_or(0),
                syscall_args(uc, Arch::Arm64),
            )
        }
    };
    // `int 0x80` from 64-bit code still speaks the 32-bit table.
    let table_arch = if arch == Arch::X86_64 { Arch::X86 } else { arch };
    let ret = dispatch(uc, st, table_arch, nr, args);
    match arch {
        Arch::X86 | Arch::X86_64 => {
            let _ = uc.reg_write(unicorn_engine::RegisterX86::EAX as i32, ret);
        }
        Arch::Arm => {
            let _ = uc.reg_write(unicorn_engine::RegisterARM::R0 as i32, ret);
        }
        Arch::Arm64 => {
            let _ = uc.reg_write(unicorn_engine::RegisterARM64::X0 as i32, ret);
        }
    }
    true
}

/// The x86-64 `syscall` instruction.
pub fn x86_syscall(uc: &mut Uc<'_>, st: &mut State, _arch: Arch) {
    let nr = uc
        .reg_read(unicorn_engine::RegisterX86::RAX as i32)
        .unwrap_or(0);
    let args = syscall_args(uc, Arch::X86_64);
    let ret = dispatch(uc, st, Arch::X86_64, nr, args);
    let _ = uc.reg_write(unicorn_engine::RegisterX86::RAX as i32, ret);
}

fn dispatch(uc: &mut Uc<'_>, st: &mut State, arch: Arch, nr: u64, args: [u64; 6]) -> u64 {
    let sys = classify(arch, nr);
    match sys {
        Sys::Read => {
            let data = vfs::read(st, args[0], args[2] as usize);
            write_bytes(uc, args[1], &data);
            data.len() as u64
        }
        Sys::Write => {
            let data = read_bytes(uc, args[1], args[2] as usize).unwrap_or_default();
            vfs::write(st, args[0], &data) as u64
        }
        Sys::Open => {
            let path = String::from_utf8_lossy(&read_cstr(uc, args[0], 4096)).to_string();
            let flags = args[1];
            let create = flags & 0x40 != 0;
            let writable = flags & 0x3 != 0;
            vfs::open(st, &path, writable, create).unwrap_or(u64::MAX)
        }
        Sys::OpenAt => {
            let path = String::from_utf8_lossy(&read_cstr(uc, args[1], 4096)).to_string();
            let flags = args[2];
            let create = flags & 0x40 != 0;
            let writable = flags & 0x3 != 0;
            vfs::open(st, &path, writable, create).unwrap_or(u64::MAX)
        }
        Sys::Close => {
            vfs::close(st, args[0]);
            0
        }
        Sys::Lseek => {
            let off = args[1] as i64;
            vfs::seek(st, args[0], off, args[2] as u32) as u64
        }
        Sys::Fstat => {
            let buf = args[1];
            if buf != 0 {
                let size = if arch.ptr_size() == 8 { 144 } else { 108 };
                write_bytes(uc, buf, &vec![0u8; size]);
            }
            0
        }
        Sys::GetPid | Sys::GetPpid | Sys::GetTid | Sys::GetUid | Sys::GetEuid | Sys::GetGid
        | Sys::GetEgid => 1,
        Sys::Exit | Sys::ExitGroup => {
            st.halt(uc, Stop::Exited((args[0] & 0xff) as i32), "exit syscall");
            0
        }
        Sys::ClockGettime => {
            fill_timespec(uc, arch, args[1], st.now_secs());
            0
        }
        Sys::Gettimeofday => {
            fill_timeval(uc, arch, args[0], st.now_secs());
            0
        }
        Sys::Time => {
            let secs = st.now_secs() as u64;
            if args[0] != 0 {
                if arch.ptr_size() == 8 {
                    write_bytes(uc, args[0], &secs.to_le_bytes());
                } else {
                    write_bytes(uc, args[0], &(secs as u32).to_le_bytes());
                }
            }
            secs
        }
        Sys::Ptrace => 0,
        Sys::Getrandom => {
            let len = args[1] as usize;
            let bytes = st.fill_random(len);
            write_bytes(uc, args[0], &bytes);
            len as u64
        }
        Sys::Brk => {
            if args[0] != 0 {
                st.heap = args[0].max(st.heap);
            }
            st.heap
        }
        Sys::Mmap => st.alloc(uc, args[1].max(1) as usize),
        Sys::Munmap | Sys::Mprotect | Sys::ArchPrctl | Sys::Futex => 0,
        Sys::Uname => {
            // struct utsname: six 65-byte fields.
            let mut buf = [0u8; 390];
            for (i, value) in ["Linux", "rekit", "6.0.0", "#1 SMP", "x86_64", "(none)"]
                .iter()
                .enumerate()
            {
                let bytes = value.as_bytes();
                let take = bytes.len().min(64);
                buf[i * 65..i * 65 + take].copy_from_slice(&bytes[..take]);
            }
            write_bytes(uc, args[0], &buf);
            0
        }
        Sys::Access => 0,
        Sys::Readlink => u64::MAX,
        Sys::Other => {
            st.notes.push(format!("syscall {nr} not implemented"));
            0
        }
    }
}

fn fill_timespec(uc: &mut Uc<'_>, arch: Arch, ptr: u64, seconds: f64) {
    if ptr == 0 {
        return;
    }
    let secs = seconds as i64;
    let nsec = ((seconds - secs as f64) * 1_000_000_000.0) as i64;
    if arch.ptr_size() == 8 {
        write_bytes(uc, ptr, &secs.to_le_bytes());
        write_bytes(uc, ptr + 8, &nsec.to_le_bytes());
    } else {
        write_bytes(uc, ptr, &(secs as u32).to_le_bytes());
        write_bytes(uc, ptr + 4, &(nsec as u32).to_le_bytes());
    }
}

fn fill_timeval(uc: &mut Uc<'_>, arch: Arch, ptr: u64, seconds: f64) {
    if ptr == 0 {
        return;
    }
    let secs = seconds as i64;
    let usec = ((seconds - secs as f64) * 1_000_000.0) as i64;
    if arch.ptr_size() == 8 {
        write_bytes(uc, ptr, &secs.to_le_bytes());
        write_bytes(uc, ptr + 8, &usec.to_le_bytes());
    } else {
        write_bytes(uc, ptr, &(secs as u32).to_le_bytes());
        write_bytes(uc, ptr + 4, &(usec as u32).to_le_bytes());
    }
}
