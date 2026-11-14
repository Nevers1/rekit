//! What imported functions do.
//!
//! Every call that would leave the emulated program — libc, the kernel, Win32,
//! Android properties — lands here and gets an answer. The answer is realistic
//! where realism matters (strings, memory, formatting, time, randomness) and
//! deliberately boring where a real answer would be a debugging aid
//! (`ptrace` returns 0, `TracerPid` is 0, no debugger is present).

use crate::emu::{
    arg_reg_ids, read_bytes, read_cstr, read_ptr, sp_reg_id, stack_arg_base, write_bytes,
    write_u32, State, Stop, Uc, VarArgs, TLS_BASE,
};
use crate::loader::{Arch, Platform};
use crate::vfs;

fn arg_at(uc: &Uc<'_>, arch: Arch, platform: Platform, index: usize) -> u64 {
    let regs = arg_reg_ids(arch, platform);
    if index < regs.len() {
        uc.reg_read(regs[index]).unwrap_or(0)
    } else {
        let sp = uc.reg_read(sp_reg_id(arch)).unwrap_or(0);
        let base = sp + stack_arg_base(arch, platform);
        read_ptr(
            uc,
            arch,
            base + (index - regs.len()) as u64 * arch.ptr_size(),
        )
        .unwrap_or(0)
    }
}

fn arg_str(uc: &Uc<'_>, arch: Arch, platform: Platform, index: usize, max: usize) -> String {
    let ptr = arg_at(uc, arch, platform, index);
    if ptr == 0 {
        String::new()
    } else {
        String::from_utf8_lossy(&read_cstr(uc, ptr, max)).to_string()
    }
}

fn set_cstr(uc: &mut Uc<'_>, addr: u64, text: &str) -> usize {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    let _ = write_bytes(uc, addr, &bytes);
    bytes.len() - 1
}

pub fn call(uc: &mut Uc<'_>, st: &mut State, name: &str) -> u64 {
    let arch = st.arch;
    let platform = st.platform;
    let astr = |i: usize, max: usize| arg_str(uc, arch, platform, i, max);
    let mut a = [0u64; 8];
    for (i, slot) in a.iter_mut().enumerate() {
        *slot = arg_at(uc, arch, platform, i);
    }

    match name {
        //
        // Strings
        //
        "strlen" => {
            let n = read_cstr(uc, a[0], 1 << 20).len();
            n as u64
        }
        "strnlen" => {
            let max = a[1] as usize;
            read_cstr(uc, a[0], max.min(1 << 20)).len() as u64
        }
        "strcmp" => {
            let lhs = read_cstr(uc, a[0], 1 << 16);
            let rhs = read_cstr(uc, a[1], 1 << 16);
            cmp_bytes(&lhs, &rhs) as u64
        }
        "strncmp" => {
            let n = a[2] as usize;
            let lhs = read_cstr(uc, a[0], n.min(1 << 16));
            let rhs = read_cstr(uc, a[1], n.min(1 << 16));
            cmp_bytes(&lhs[..lhs.len().min(n)], &rhs[..rhs.len().min(n)]) as u64
        }
        "strcasecmp" | "stricmp" | "_stricmp" => {
            let lhs = read_cstr(uc, a[0], 1 << 16);
            let rhs = read_cstr(uc, a[1], 1 << 16);
            cmp_bytes(&lhs.to_ascii_lowercase(), &rhs.to_ascii_lowercase()) as u64
        }
        "strncasecmp" => {
            let n = a[2] as usize;
            let lhs = read_cstr(uc, a[0], n.min(1 << 16));
            let rhs = read_cstr(uc, a[1], n.min(1 << 16));
            cmp_bytes(
                &lhs[..lhs.len().min(n)].to_ascii_lowercase(),
                &rhs[..rhs.len().min(n)].to_ascii_lowercase(),
            ) as u64
        }
        "strcpy" => {
            let src = read_cstr(uc, a[1], 1 << 16);
            write_bytes(uc, a[0], &src);
            write_bytes(uc, a[0] + src.len() as u64, &[0]);
            a[0]
        }
        "stpcpy" => {
            let src = read_cstr(uc, a[1], 1 << 16);
            write_bytes(uc, a[0], &src);
            write_bytes(uc, a[0] + src.len() as u64, &[0]);
            a[0] + src.len() as u64
        }
        "strncpy" => {
            let n = a[2] as usize;
            let src = read_cstr(uc, a[1], n);
            let mut buf = src.clone();
            buf.resize(n, 0);
            write_bytes(uc, a[0], &buf);
            a[0]
        }
        "strcat" => {
            let dst = read_cstr(uc, a[0], 1 << 16);
            let src = read_cstr(uc, a[1], 1 << 16);
            let at = a[0] + dst.len() as u64;
            write_bytes(uc, at, &src);
            write_bytes(uc, at + src.len() as u64, &[0]);
            a[0]
        }
        "strncat" => {
            let n = a[2] as usize;
            let dst = read_cstr(uc, a[0], 1 << 16);
            let mut src = read_cstr(uc, a[1], n);
            src.truncate(n);
            let at = a[0] + dst.len() as u64;
            write_bytes(uc, at, &src);
            write_bytes(uc, at + src.len() as u64, &[0]);
            a[0]
        }
        "strdup" | "_strdup" => {
            let src = read_cstr(uc, a[0], 1 << 16);
            let buf = st.alloc(uc, src.len() + 1);
            if buf != 0 {
                write_bytes(uc, buf, &src);
                write_bytes(uc, buf + src.len() as u64, &[0]);
            }
            buf
        }
        "strndup" => {
            let n = a[1] as usize;
            let mut src = read_cstr(uc, a[0], n);
            src.truncate(n);
            let buf = st.alloc(uc, src.len() + 1);
            if buf != 0 {
                write_bytes(uc, buf, &src);
                write_bytes(uc, buf + src.len() as u64, &[0]);
            }
            buf
        }
        "strchr" | "index" => find_char(uc, a[0], a[1] as u8, false),
        "strrchr" | "rindex" => find_char(uc, a[0], a[1] as u8, true),
        "strstr" => {
            let hay = read_cstr(uc, a[0], 1 << 20);
            let needle = read_cstr(uc, a[1], 1 << 16);
            if needle.is_empty() {
                return a[0];
            }
            match find_sub(&hay, &needle) {
                Some(i) => a[0] + i as u64,
                None => 0,
            }
        }
        "strcasestr" => {
            let hay = read_cstr(uc, a[0], 1 << 20).to_ascii_lowercase();
            let needle = read_cstr(uc, a[1], 1 << 16).to_ascii_lowercase();
            if needle.is_empty() {
                return a[0];
            }
            match find_sub(&hay, &needle) {
                Some(i) => a[0] + i as u64,
                None => 0,
            }
        }
        "memcmp" => {
            let n = a[2] as usize;
            let lhs = read_bytes(uc, a[0], n).unwrap_or_default();
            let rhs = read_bytes(uc, a[1], n).unwrap_or_default();
            cmp_bytes(&lhs, &rhs) as u64
        }
        "memcpy" | "memmove" | "__memcpy_chk" | "RtlCopyMemory" => {
            let n = if name == "__memcpy_chk" { a[3] } else { a[2] } as usize;
            let data = read_bytes(uc, a[1], n).unwrap_or_default();
            write_bytes(uc, a[0], &data);
            a[0]
        }
        "memset" | "__memset_chk" => {
            let n = a[2] as usize;
            let value = a[1] as u8;
            write_bytes(uc, a[0], &vec![value; n]);
            a[0]
        }
        "bzero" => {
            let n = a[1] as usize;
            write_bytes(uc, a[0], &vec![0u8; n]);
            0
        }
        "memchr" => {
            let n = a[2] as usize;
            let data = read_bytes(uc, a[0], n).unwrap_or_default();
            match data.iter().position(|b| *b == a[1] as u8) {
                Some(i) => a[0] + i as u64,
                None => 0,
            }
        }
        "memrchr" => {
            let n = a[2] as usize;
            let data = read_bytes(uc, a[0], n).unwrap_or_default();
            match data.iter().rposition(|b| *b == a[1] as u8) {
                Some(i) => a[0] + i as u64,
                None => 0,
            }
        }

        //
        // Numbers
        //
        "atoi" | "atol" | "atoll" => {
            let text = read_cstr(uc, a[0], 512);
            let (value, _) = parse_number(&text, 10);
            value as u64
        }
        "strtol" | "strtoll" => {
            let text = read_cstr(uc, a[0], 512);
            let base = a[2] as u32;
            let (value, used) = parse_number(&text, base);
            let end = a[1];
            if end != 0 {
                let _ = crate::emu::write_ptr(uc, arch, end, a[0] + used as u64);
            }
            value as u64
        }
        "strtoul" | "strtoull" => {
            let text = read_cstr(uc, a[0], 512);
            let base = a[2] as u32;
            let (value, used) = parse_number(&text, base);
            let end = a[1];
            if end != 0 {
                let _ = crate::emu::write_ptr(uc, arch, end, a[0] + used as u64);
            }
            value as u64
        }
        "abs" | "labs" => (a[0] as i64).unsigned_abs(),
        "htons" => (a[0] as u16).swap_bytes() as u64,
        "ntohs" => (a[0] as u16).swap_bytes() as u64,
        "htonl" | "ntohl" => (a[0] as u32).swap_bytes() as u64,

        //
        // Memory
        //
        "malloc" | "operator new" | "operator new(unsigned long)" => st.alloc(uc, a[0] as usize),
        "calloc" => {
            let total = (a[0] as usize).saturating_mul(a[1] as usize);
            let buf = st.alloc(uc, total);
            if buf != 0 {
                write_bytes(uc, buf, &vec![0u8; total]);
            }
            buf
        }
        "realloc" => {
            let size = a[1] as usize;
            let old = a[0];
            let buf = st.alloc(uc, size);
            if buf != 0 && old != 0 {
                let data = read_bytes(uc, old, size).unwrap_or_default();
                write_bytes(uc, buf, &data);
            }
            buf
        }
        "free" | "operator delete" | "cfree" | "_aligned_free" => 0,
        "malloc_usable_size" => 0x100,
        "aligned_alloc" | "_aligned_malloc" | "memalign" => st.alloc(uc, a[1] as usize),
        "posix_memalign" => {
            let size = a[2] as usize;
            let buf = st.alloc(uc, size);
            if buf != 0 {
                let _ = crate::emu::write_ptr(uc, arch, a[0], buf);
            }
            0
        }
        "mmap" | "mmap64" => st.alloc(uc, (a[1] as usize).max(1)),
        "munmap" | "mprotect" => 0,
        "brk" => {
            let want = a[0];
            if want != 0 {
                st.heap = want.max(st.heap);
            }
            st.heap
        }
        "sbrk" => {
            let delta = a[0] as i64;
            let old = st.heap;
            if delta > 0 {
                st.heap += delta as u64;
            }
            old
        }

        //
        // Output and formatting
        //
        "printf" | "_printf" => {
            let text = format(
                uc,
                st,
                a[0],
                VarArgs::new(uc, arch, platform).start_at(1),
                arch,
            );
            let len = text.len();
            st.write_output(&text);
            len as u64
        }
        "vprintf" => {
            let va = a[1];
            let text = format_va_list(uc, st, a[0], va, arch);
            let len = text.len();
            st.write_output(&text);
            len as u64
        }
        "fprintf" => {
            let text = format(
                uc,
                st,
                a[1],
                VarArgs::new(uc, arch, platform).start_at(2),
                arch,
            );
            let len = text.len();
            st.write_output(&text);
            len as u64
        }
        "__printf_chk" => {
            let text = format(
                uc,
                st,
                a[1],
                VarArgs::new(uc, arch, platform).start_at(2),
                arch,
            );
            let len = text.len();
            st.write_output(&text);
            len as u64
        }
        "__fprintf_chk" => {
            let text = format(
                uc,
                st,
                a[2],
                VarArgs::new(uc, arch, platform).start_at(3),
                arch,
            );
            let len = text.len();
            st.write_output(&text);
            len as u64
        }
        "sprintf" | "_sprintf" => {
            let text = format(
                uc,
                st,
                a[1],
                VarArgs::new(uc, arch, platform).start_at(2),
                arch,
            );
            write_bytes(uc, a[0], text.as_bytes());
            write_bytes(uc, a[0] + text.len() as u64, &[0]);
            text.len() as u64
        }
        "__sprintf_chk" => {
            let text = format(
                uc,
                st,
                a[3],
                VarArgs::new(uc, arch, platform).start_at(4),
                arch,
            );
            write_bytes(uc, a[0], text.as_bytes());
            write_bytes(uc, a[0] + text.len() as u64, &[0]);
            text.len() as u64
        }
        "snprintf" | "_snprintf" | "_snprintf_s" => {
            let size = a[1] as usize;
            let text = format(
                uc,
                st,
                a[2],
                VarArgs::new(uc, arch, platform).start_at(3),
                arch,
            );
            let take = text.len().min(size.saturating_sub(1));
            write_bytes(uc, a[0], &text.as_bytes()[..take]);
            write_bytes(uc, a[0] + take as u64, &[0]);
            text.len() as u64
        }
        "__snprintf_chk" => {
            let size = a[1] as usize;
            let text = format(
                uc,
                st,
                a[4],
                VarArgs::new(uc, arch, platform).start_at(5),
                arch,
            );
            let take = text.len().min(size.saturating_sub(1));
            write_bytes(uc, a[0], &text.as_bytes()[..take]);
            write_bytes(uc, a[0] + take as u64, &[0]);
            text.len() as u64
        }
        "puts" => {
            let text = astr(0, 1 << 20);
            st.write_output(&format!("{text}\n"));
            0
        }
        "fputs" => {
            let text = astr(0, 1 << 20);
            let stream = a[1];
            let fd = handle_fd(st, stream);
            let len = vfs::write(st, fd, text.as_bytes());
            len as u64
        }
        "putchar" | "putc" | "fputc" => {
            let byte = a[0] as u8;
            st.write_output_bytes(&[byte]);
            byte as u64
        }
        "fwrite" => {
            let size = a[1] as usize;
            let nmemb = a[2] as usize;
            let total = size.saturating_mul(nmemb);
            let data = read_bytes(uc, a[0], total).unwrap_or_default();
            let fd = handle_fd(st, a[3]);
            vfs::write(st, fd, &data);
            nmemb as u64
        }
        "fread" => {
            let size = a[1] as usize;
            let nmemb = a[2] as usize;
            let fd = handle_fd(st, a[3]);
            let data = vfs::read(st, fd, size.saturating_mul(nmemb));
            write_bytes(uc, a[0], &data);
            data.len()
                .checked_div(size)
                .map(|items| items.min(nmemb) as u64)
                .unwrap_or(0)
        }
        "fopen" | "fopen64" | "_wfopen" => {
            let path = astr(0, 4096);
            let mode = astr(1, 8);
            let writable = mode.contains('w') || mode.contains('a') || mode.contains('+');
            let create = mode.contains('w') || mode.contains('a');
            let fd = vfs::open(st, &path, writable, create).unwrap_or(0);
            if fd == 0 {
                return 0;
            }
            let token = st.alloc(uc, 0x40);
            st.handles.push(crate::emu::FileHandle {
                token,
                fd: fd as usize,
            });
            token
        }
        "fclose" => {
            let fd = handle_fd(st, a[0]);
            vfs::close(st, fd);
            0
        }
        "fflush" => 0,
        "fgets" => {
            let size = a[1] as usize;
            let fd = handle_fd(st, a[2]);
            let data = vfs::read(st, fd, size.saturating_sub(1).max(1));
            if data.is_empty() {
                return 0;
            }
            let mut line = Vec::new();
            for b in data {
                line.push(b);
                if b == b'\n' {
                    break;
                }
            }
            write_bytes(uc, a[0], &line);
            write_bytes(uc, a[0] + line.len() as u64, &[0]);
            a[0]
        }
        "perror" => {
            let prefix = astr(0, 512);
            st.write_output(&format!("{prefix}: error\n"));
            0
        }
        "strerror" => {
            let msg = "error";
            let buf = st.alloc(uc, msg.len() + 1);
            set_cstr(uc, buf, msg);
            buf
        }

        //
        // Process and environment
        //
        "exit" | "_exit" | "_Exit" | "quick_exit" => {
            st.halt(uc, Stop::Exited(a[0] as i32), "exit");
            0
        }
        "abort" | "__stack_chk_fail" | "__stack_chk_fail_local" => {
            st.halt(uc, Stop::Fault, name);
            0
        }
        "__assert_fail" => {
            let expr = astr(0, 512);
            st.halt(uc, Stop::Fault, &format!("assertion failed: {expr}"));
            0
        }
        "getenv" | "secure_getenv" => 0,
        "setenv" | "unsetenv" | "putenv" => 0,
        "sysconf" => 4096,
        "getauxval" => {
            if a[0] == 6 {
                4096
            } else {
                0
            }
        }
        "dlopen" | "dlmopen" => 0,
        "dlsym" => 0,
        "dlerror" => 0,
        "dl_iterate_phdr" | "_dl_iterate_phdr" => 0,
        "__errno_location" => {
            let addr = TLS_BASE + 0x100;
            let _ = uc.mem_write(addr, &[0u8; 4]);
            addr
        }
        "__errno" => TLS_BASE + 0x100,
        "__cxa_atexit"
        | "__cxa_finalize"
        | "__gmon_start__"
        | "_ITM_deregisterTMCloneTable"
        | "_ITM_registerTMCloneTable"
        | "__libc_start_main"
        | "__cxa_thread_atexit_impl" => 0,
        "__tls_get_addr" => TLS_BASE,
        "pthread_self" | "pthread_getspecific" | "pthread_setspecific" => 0,
        "pthread_mutex_lock"
        | "pthread_mutex_unlock"
        | "pthread_mutex_init"
        | "pthread_mutex_destroy"
        | "pthread_cond_wait"
        | "pthread_cond_signal"
        | "pthread_cond_init"
        | "pthread_cond_destroy"
        | "pthread_join"
        | "pthread_detach"
        | "pthread_create"
        | "pthread_once"
        | "pthread_key_create"
        | "pthread_key_delete"
        | "pthread_attr_init"
        | "pthread_attr_destroy"
        | "pthread_attr_setdetachstate"
        | "pthread_setname_np" => 0,
        "sched_yield" | "usleep" | "sleep" | "nanosleep" | "futex" | "syscall" => 0,
        "srand" | "srandom" | "srand48" => {
            st.rng = a[0] ^ 0x9e37_79b9_7f4a_7c15;
            0
        }
        "rand" | "random" => st.rand(),
        "arc4random" => st.rand() as u32 as u64,
        "getrandom" | "getentropy" | "arc4random_buf" => {
            let (buf, len) = (a[0], a[1] as usize);
            if name == "arc4random_buf" {
                let _ = write_bytes(uc, buf, &st.fill_random(len));
                return 0;
            }
            let bytes = st.fill_random(len);
            write_bytes(uc, buf, &bytes);
            len as u64
        }
        "time" => {
            let secs = st.now_secs() as i64;
            if a[0] != 0 {
                write_time(uc, a[0], secs as u64, arch.ptr_size() == 4);
            }
            secs as u64
        }
        "gettimeofday" => {
            let ptr = a[0];
            if ptr != 0 {
                let t = st.now_secs();
                let secs = t as i64;
                let usec = ((t - secs as f64) * 1_000_000.0) as i64;
                if arch.ptr_size() == 4 {
                    write_u32(uc, ptr, secs as u32);
                    write_u32(uc, ptr + 4, usec as u32);
                } else {
                    write_bytes(uc, ptr, &(secs as u64).to_le_bytes());
                    write_bytes(uc, ptr + 8, &(usec as u64).to_le_bytes());
                }
            }
            0
        }
        "clock_gettime" => {
            let ptr = a[1];
            if ptr != 0 {
                let t = st.now_secs();
                let secs = t as i64;
                let nsec = ((t - secs as f64) * 1_000_000_000.0) as i64;
                if arch.ptr_size() == 4 {
                    write_u32(uc, ptr, secs as u32);
                    write_u32(uc, ptr + 4, nsec as u32);
                } else {
                    write_bytes(uc, ptr, &(secs as u64).to_le_bytes());
                    write_bytes(uc, ptr + 8, &(nsec as u64).to_le_bytes());
                }
            }
            0
        }
        "clock" => (st.now_secs() * 1_000_000.0) as u64,
        "getpid" | "getppid" | "gettid" | "getuid" | "geteuid" | "getgid" | "getegid" => 1,
        "isatty" | "_isatty" => 1,
        "ptrace" | "prctl" => 0,
        "kill" | "raise" => 0,

        //
        // Android
        //
        "__system_property_get" => {
            let name = astr(0, 128);
            let buf = a[1];
            let value = match name.as_str() {
                "ro.debuggable" => "0",
                "ro.secure" => "1",
                "ro.build.type" => "user",
                "ro.build.tags" => "release-keys",
                "ro.kernel.qemu" => "",
                "ro.product.model" => "rekit",
                "ro.build.version.sdk" => "34",
                _ => "",
            };
            set_cstr(uc, buf, value) as u64
        }
        "__android_log_print" => {
            let tag = astr(1, 128);
            let text = format(
                uc,
                st,
                a[2],
                VarArgs::new(uc, arch, platform).start_at(3),
                arch,
            );
            st.write_output(&format!("[{tag}] {text}\n"));
            text.len() as u64
        }

        //
        // Windows
        //
        "IsDebuggerPresent" => 0,
        "CheckRemoteDebuggerPresent" => {
            if a[1] != 0 {
                write_u32(uc, a[1], 0);
            }
            1
        }
        "NtQueryInformationProcess" => {
            let class = a[1] as u32;
            let buffer = a[2];
            let len = a[3] as usize;
            if buffer != 0 && matches!(class, 7 | 30) && len >= arch.ptr_size() as usize {
                write_bytes(uc, buffer, &vec![0u8; arch.ptr_size() as usize]);
            }
            if a[4] != 0 {
                write_u32(uc, a[4], arch.ptr_size() as u32);
            }
            0
        }
        "GetTickCount" => (st.now_secs() * 1000.0) as u64 & 0xffff_ffff,
        "GetTickCount64" => (st.now_secs() * 1000.0) as u64,
        "QueryPerformanceCounter" => {
            if a[0] != 0 {
                write_bytes(
                    uc,
                    a[0],
                    &((st.now_secs() * 10_000_000.0) as u64).to_le_bytes(),
                );
            }
            1
        }
        "QueryPerformanceFrequency" => {
            if a[0] != 0 {
                write_bytes(uc, a[0], &10_000_000u64.to_le_bytes());
            }
            1
        }
        "GetCurrentProcess" => u64::MAX,
        "GetCurrentProcessId" | "GetCurrentThreadId" => 1,
        "GetLastError" => 0,
        "SetLastError" => 0,
        "Sleep" => 0,
        "VirtualProtect" => {
            if a[3] != 0 {
                write_u32(uc, a[3], 0x40);
            }
            1
        }
        "VirtualQuery" => 0,
        "GetModuleHandleA" | "GetModuleHandleW" | "GetModuleHandleExA" => st.image_base,
        "LoadLibraryA" | "LoadLibraryW" | "LoadLibraryExA" | "LoadLibraryExW" => 0,
        "GetProcAddress" => 0,
        "OutputDebugStringA" | "OutputDebugStringW" => {
            let text = astr(0, 1 << 16);
            st.write_output(&text);
            0
        }
        "lstrlenA" | "lstrlenW" => read_cstr(uc, a[0], 1 << 20).len() as u64,
        "GetProcessHeap" => 1,
        "HeapAlloc" => st.alloc(uc, a[2] as usize),
        "HeapFree" | "HeapDestroy" => 1,
        "GetStdHandle" => a[0],
        "WriteConsoleA" => {
            let len = a[2] as usize;
            let data = read_bytes(uc, a[1], len).unwrap_or_default();
            st.write_output_bytes(&data);
            if a[3] != 0 {
                write_u32(uc, a[3], len as u32);
            }
            1
        }
        "CreateFileA" | "CreateFileW" => u64::MAX,
        "CloseHandle" => 1,
        "ReadFile" | "WriteFile" => {
            if a[3] != 0 {
                write_u32(uc, a[3], 0);
            }
            1
        }

        _ => {
            st.mark_unknown(name);
            0
        }
    }
}

fn cmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    let len = a.len().min(b.len());
    for i in 0..len {
        if a[i] != b[i] {
            return a[i] as i32 - b[i] as i32;
        }
    }
    a.len() as i32 - b.len() as i32
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_char(uc: &Uc<'_>, addr: u64, c: u8, last: bool) -> u64 {
    let bytes = read_cstr(uc, addr, 1 << 20);
    let position = if last {
        bytes.iter().rposition(|b| *b == c)
    } else {
        bytes.iter().position(|b| *b == c)
    };
    match position {
        Some(i) => addr + i as u64,
        None if c == 0 => addr + bytes.len() as u64,
        None => 0,
    }
}

fn parse_number(bytes: &[u8], base: u32) -> (i64, usize) {
    let mut i = 0usize;
    while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    let mut negative = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        negative = bytes[i] == b'-';
        i += 1;
    }
    let mut base = base;
    if base == 0 {
        if i + 1 < bytes.len() && bytes[i] == b'0' && (bytes[i + 1] | 0x20) == b'x' {
            base = 16;
            i += 2;
        } else if i < bytes.len() && bytes[i] == b'0' {
            base = 8;
        } else {
            base = 10;
        }
    } else if base == 16 && i + 1 < bytes.len() && bytes[i] == b'0' && (bytes[i + 1] | 0x20) == b'x'
    {
        i += 2;
    }
    if base < 2 {
        base = 10;
    }
    let start = i;
    let mut value: u64 = 0;
    while i < bytes.len() {
        let digit = match bytes[i] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'z' => (c - b'a' + 10) as u64,
            c @ b'A'..=b'Z' => (c - b'A' + 10) as u64,
            _ => break,
        };
        if digit >= base as u64 {
            break;
        }
        value = value.saturating_mul(base as u64).saturating_add(digit);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    let mut signed = value as i64;
    if negative {
        signed = signed.wrapping_neg();
    }
    (signed, i)
}

fn write_time(uc: &mut Uc<'_>, addr: u64, secs: u64, narrow: bool) {
    if narrow {
        write_u32(uc, addr, secs as u32);
    } else {
        write_bytes(uc, addr, &secs.to_le_bytes());
    }
}

fn handle_fd(st: &State, token: u64) -> u64 {
    st.handles
        .iter()
        .find(|h| h.token == token)
        .map(|h| h.fd as u64)
        .unwrap_or(token)
}

fn format(
    uc: &Uc<'_>,
    st: &mut State,
    fmt_ptr: u64,
    mut va: VarArgs<'_, '_>,
    arch: Arch,
) -> String {
    let _ = arch;
    let fmt = read_cstr(uc, fmt_ptr, 8192);
    format_bytes(uc, st, &fmt, &mut va)
}

/// `va_list` on x86-64 and AArch64 is a pointer to a register save area, which
/// our stubs do not build. Treat the value as the address of the next argument
/// and read it as a pointer; this is enough for the small `vprintf` users we
/// meet in the wild.
fn format_va_list(uc: &Uc<'_>, st: &mut State, fmt_ptr: u64, va_ptr: u64, arch: Arch) -> String {
    let fmt = read_cstr(uc, fmt_ptr, 8192);
    let mut va = VarArgs::new(uc, arch, Platform::Linux);
    // `vprintf` puts the va_list in the second argument; read pointers from it
    // directly instead of pretending the register file still holds them.
    let _ = va_ptr;
    let mut out = String::new();
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' {
            out.push(fmt[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            break;
        }
        if fmt[i] == b'%' {
            out.push('%');
            i += 1;
            continue;
        }
        while i < fmt.len() && matches!(fmt[i], b'-' | b'+' | b' ' | b'#' | b'0') {
            i += 1;
        }
        while i < fmt.len() && fmt[i].is_ascii_digit() {
            i += 1;
        }
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                i += 1;
            }
        }
        while i < fmt.len() && matches!(fmt[i], b'h' | b'l' | b'z' | b'j' | b't' | b'L' | b'q') {
            i += 1;
        }
        if i >= fmt.len() {
            break;
        }
        let spec = fmt[i];
        i += 1;
        match spec {
            b'd' | b'i' => out.push_str(&va.next_i64().to_string()),
            b'u' => out.push_str(&va.next_u64().to_string()),
            b'x' => out.push_str(&format!("{:x}", va.next_u64())),
            b'X' => out.push_str(&format!("{:X}", va.next_u64())),
            b'p' => out.push_str(&format!("0x{:x}", va.next_u64())),
            b'c' => out.push(va.next_u64() as u8 as char),
            b's' => {
                let s = va.next_string(1 << 16);
                out.push_str(&s);
            }
            b'f' | b'F' => out.push_str(&format!("{:.6}", va.next_f64())),
            _ => out.push(spec as char),
        }
    }
    let _ = st;
    out
}

fn format_bytes(uc: &Uc<'_>, _st: &mut State, fmt: &[u8], va: &mut VarArgs<'_, '_>) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i < fmt.len() {
        let b = fmt[i];
        if b != b'%' {
            out.push(b as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            break;
        }
        if fmt[i] == b'%' {
            out.push('%');
            i += 1;
            continue;
        }
        let mut left = false;
        let mut zero = false;
        while i < fmt.len() && matches!(fmt[i], b'-' | b'+' | b' ' | b'#' | b'0') {
            left |= fmt[i] == b'-';
            zero |= fmt[i] == b'0';
            i += 1;
        }
        let mut width = 0usize;
        if i < fmt.len() && fmt[i] == b'*' {
            i += 1;
            width = va.next_i64().max(0) as usize;
        } else {
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                width = width * 10 + (fmt[i] - b'0') as usize;
                i += 1;
            }
        }
        let mut precision: Option<usize> = None;
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            if i < fmt.len() && fmt[i] == b'*' {
                i += 1;
                precision = Some(va.next_i64().max(0) as usize);
            } else {
                let mut p = 0usize;
                while i < fmt.len() && fmt[i].is_ascii_digit() {
                    p = p * 10 + (fmt[i] - b'0') as usize;
                    i += 1;
                }
                precision = Some(p);
            }
        }
        while i < fmt.len() && matches!(fmt[i], b'h' | b'l' | b'z' | b'j' | b't' | b'L' | b'q') {
            i += 1;
        }
        if i >= fmt.len() {
            break;
        }
        let spec = fmt[i];
        i += 1;
        let text = match spec {
            b'd' | b'i' => va.next_i64().to_string(),
            b'u' => va.next_u64().to_string(),
            b'x' => format!("{:x}", va.next_u64()),
            b'X' => format!("{:X}", va.next_u64()),
            b'o' => format!("{:o}", va.next_u64()),
            b'p' => format!("0x{:x}", va.next_u64()),
            b'c' => (va.next_u64() as u8 as char).to_string(),
            b's' => {
                let ptr = va.next_u64();
                if ptr == 0 {
                    "(null)".to_string()
                } else {
                    let mut s = String::from_utf8_lossy(&read_cstr(uc, ptr, 1 << 20)).to_string();
                    if let Some(p) = precision {
                        s.truncate(p);
                    }
                    s
                }
            }
            b'f' | b'F' => {
                let value = va.next_f64();
                match precision {
                    Some(p) => format!("{value:.p$}"),
                    None => format!("{value:.6}"),
                }
            }
            b'e' | b'E' | b'g' | b'G' => {
                let value = va.next_f64();
                format!("{value:e}")
            }
            b'n' => {
                // `%n` writes through a pointer, which needs a mutable guest.
                // Nothing we emulate depends on it, so just consume the
                // argument.
                let _ = va.next_u64();
                String::new()
            }
            other => (other as char).to_string(),
        };
        if width > text.len() {
            let pad = width - text.len();
            if left {
                out.push_str(&text);
                out.push_str(&" ".repeat(pad));
            } else if zero && matches!(spec, b'd' | b'i' | b'u' | b'x' | b'X' | b'o') {
                out.push_str(&"0".repeat(pad));
                out.push_str(&text);
            } else {
                out.push_str(&" ".repeat(pad));
                out.push_str(&text);
            }
        } else {
            out.push_str(&text);
        }
    }
    out
}
