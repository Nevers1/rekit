//! The machine: maps an image, wires import stubs, sets up the ABI and runs.
//!
//! Unicorn executes the code; everything that would normally be a syscall, a
//! libc call or a window into `/proc` is answered here or in `imports`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use unicorn_engine::unicorn_const::{
    uc_error, Arch as UcArch, HookType, MemType, Mode, Prot, Query,
};
use unicorn_engine::{RegisterARM, RegisterARM64, RegisterX86, Unicorn, X86Insn};

use crate::imports;
use crate::loader::{Arch, Loaded, Platform, RelocKind};

pub type Uc<'a> = Unicorn<'a, ()>;

/// Where import thunks live. Slot 0 is the return sentinel.
pub const STUB_BASE: u64 = 0x3000_0000;
pub const STUB_STRIDE: u64 = 16;
pub const STUB_SLOTS: u64 = 2048;
pub const SENTINEL: u64 = STUB_BASE;

pub const HEAP_BASE: u64 = 0x2000_0000;
pub const HEAP_SIZE: u64 = 0x0200_0000;
pub const TLS_BASE: u64 = 0x2800_0000;

pub const STACK_SIZE: u64 = 0x0010_0000;

/// How many trace addresses to keep. A trace is for reading the start of a
/// function, not for reconstructing a million instructions.
const TRACE_KEEP: usize = 4096;
/// How many of them to disassemble for the report.
const TRACE_SHOWN: usize = 24;

#[derive(Clone, Debug)]
pub enum Arg {
    Num(u64),
    /// A `double`, passed in the floating-point registers the ABI names for
    /// them. Integer and float arguments live in different files, which is why
    /// an argument has to say which it is.
    Float(f64),
    Str(String),
    /// The fake `JNIEnv`, for a native method that expects one first.
    Env,
}

/// An argument after strings turned into heap addresses.
#[derive(Clone, Copy)]
enum Slot {
    Int(u64),
    Float(f64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Running,
    Returned,
    Exited(i32),
    InsnLimit,
    Timeout,
    Fault,
}

pub struct VFile {
    pub path: String,
    pub data: Vec<u8>,
    pub pos: usize,
    pub writable: bool,
    pub random: bool,
}

pub struct FileHandle {
    pub token: u64,
    pub fd: usize,
}

pub struct State {
    pub arch: Arch,
    pub platform: Platform,
    /// Image base, reported by `GetModuleHandle` and friends.
    pub image_base: u64,
    pub vfs: bool,
    /// Stub slot index -> imported name.
    pub import_names: Vec<String>,
    pub name_slots: HashMap<String, usize>,
    pub calls: Vec<(String, u64)>,
    pub call_index: HashMap<String, usize>,
    pub unknown: Vec<String>,
    pub unknown_seen: HashMap<String, bool>,
    pub output: String,
    pub output_limit: usize,
    pub stop: Stop,
    pub ret: u64,
    pub start: Instant,
    pub heap: u64,
    pub heap_limit: u64,
    pub rng: u64,
    pub files: Vec<VFile>,
    pub handles: Vec<FileHandle>,
    pub halted: Option<(Stop, String)>,
    pub notes: Vec<String>,
    /// First unmapped access, kept even when emulation continues past it.
    pub fault: Option<Fault>,
    /// The fake `JNIEnv` handed to native code that calls into Java.
    pub jni_env: u64,
    pub jni_table: u64,
    pub jni_vm: u64,
    pub jni_objects: HashMap<(crate::jni::Kind, u64), u64>,
    pub jni_strings: HashMap<u64, String>,
    /// The JNIEnv note is worth printing once, not once per call.
    pub jni_noted: bool,
    /// Every instruction address, when tracing was asked for.
    pub trace: Vec<u64>,
    /// Addresses whose import the caller overrode.
    pub overrides: HashMap<u64, Override>,
    /// What happened to those overrides: applied, or ignored and why.
    pub override_notes: Vec<String>,
}

impl State {
    fn new(loaded: &Loaded, vfs: bool) -> Self {
        State {
            arch: loaded.arch,
            platform: loaded.platform,
            image_base: loaded.base,
            vfs,
            import_names: vec![String::new()],
            name_slots: HashMap::new(),
            calls: Vec::new(),
            call_index: HashMap::new(),
            unknown: Vec::new(),
            unknown_seen: HashMap::new(),
            output: String::new(),
            output_limit: 1 << 20,
            stop: Stop::Running,
            ret: 0,
            start: Instant::now(),
            heap: HEAP_BASE,
            heap_limit: HEAP_BASE + HEAP_SIZE,
            rng: 0x1234_5678_9abc_def0,
            files: Vec::new(),
            handles: Vec::new(),
            halted: None,
            notes: Vec::new(),
            fault: None,
            jni_env: 0,
            jni_table: 0,
            jni_vm: 0,
            jni_objects: HashMap::new(),
            jni_strings: HashMap::new(),
            jni_noted: false,
            trace: Vec::new(),
            overrides: HashMap::new(),
            override_notes: Vec::new(),
        }
    }

    pub fn now_secs(&self) -> f64 {
        1_700_000_000.0 + self.start.elapsed().as_secs_f64()
    }

    pub fn rand(&mut self) -> u64 {
        self.rng = self
            .rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.rng
    }

    pub fn fill_random(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let v = self.rand();
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    pub fn count_call(&mut self, name: &str) {
        if let Some(&i) = self.call_index.get(name) {
            self.calls[i].1 += 1;
        } else {
            self.call_index.insert(name.to_string(), self.calls.len());
            self.calls.push((name.to_string(), 1));
        }
    }

    pub fn mark_unknown(&mut self, name: &str) {
        if self.unknown_seen.insert(name.to_string(), true).is_none() {
            self.unknown.push(name.to_string());
        }
    }

    pub fn write_output(&mut self, text: &str) {
        if self.output.len() < self.output_limit {
            let room = self.output_limit - self.output.len();
            let take = text.len().min(room);
            self.output.push_str(&text[..take]);
            if take < text.len() {
                self.output.push_str("...[truncated]");
                self.output_limit = self.output.len();
            }
        }
    }

    pub fn write_output_bytes(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        self.write_output(&text);
    }

    pub fn alloc(&mut self, uc: &mut Uc<'_>, size: usize) -> u64 {
        let size = ((size as u64) + 15) & !15;
        let size = size.max(16);
        if self.heap + size > self.heap_limit {
            let extra = ((size + 0xff_ffff) & !0xff_ffff).max(0x10_0000);
            if uc.mem_map(self.heap_limit, extra, Prot::ALL).is_err() {
                return 0;
            }
            self.heap_limit += extra;
        }
        let addr = self.heap;
        self.heap += size;
        if size <= 0x10_000 {
            let zeros = vec![0u8; size as usize];
            let _ = uc.mem_write(addr, &zeros);
        }
        addr
    }

    pub fn halt(&mut self, uc: &mut Uc<'_>, stop: Stop, reason: &str) {
        self.halted = Some((stop, reason.to_string()));
        self.stop = stop;
        let _ = uc.emu_stop();
    }
}

#[derive(serde::Serialize)]
pub struct CallCount {
    pub name: String,
    pub count: u64,
}

#[derive(serde::Serialize)]
pub struct ReturnValue {
    pub hex: String,
    pub i64: i64,
    pub u64: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub f64: Option<f64>,
}

/// The moment emulation hit memory it should not have.
///
/// Unicorn returns only "read from unmapped memory": neither the address nor
/// the instruction is in the error, so both are recorded from a memory hook and
/// the program counter. For a fuzzer this is the whole point — the address is
/// what tells you whether the input overran a buffer.
#[derive(serde::Serialize, Clone, Debug)]
pub struct Fault {
    /// read, write or fetch
    pub access: &'static str,
    /// Address the access went to.
    pub address: u64,
    /// Size in bytes.
    pub size: u64,
    /// Instruction that made the access.
    pub pc: u64,
}

#[derive(serde::Serialize)]
pub struct Report {
    pub ok: bool,
    pub arch: String,
    pub platform: String,
    pub symbol: Option<String>,
    pub address: String,
    pub stop: String,
    #[serde(rename = "return")]
    pub ret: ReturnValue,
    pub output: String,
    pub calls: Vec<CallCount>,
    pub unimplemented: Vec<String>,
    /// Files the guest tried to open, in order. A licence check that reads
    /// `/proc/self/status` shows up here even when it says nothing.
    pub files: Vec<String>,
    pub notes: Vec<String>,
    /// Where execution hit unmapped memory, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fault: Option<Fault>,
    /// Registers asked for with `--regs`, name to hex value.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub regs: std::collections::BTreeMap<String, String>,
    /// Memory read back after the run: the buffer a function decrypted into.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<Readout>,
    /// First instructions of the trace, disassembled.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disasm: Vec<String>,
    /// Forced returns that were applied, and any that were ignored because the
    /// stub has to hand back a usable pointer.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<String>,
    pub elapsed_ms: u64,
}

/// One `--read addr:size:label` answered after the run.
#[derive(serde::Serialize)]
pub struct Readout {
    pub label: String,
    pub addr: String,
    pub size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ascii: Option<String>,
    /// Set when the range was not mapped or ran off the end of memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A read to perform once the function has returned.
#[derive(Clone, Debug)]
pub struct ReadRange {
    pub addr: u64,
    pub size: usize,
    pub label: String,
}

/// An import call the caller wants to answer itself.
///
/// `ret` is the value to hand back instead of the stub's own answer. It is
/// honoured for anything that computes a value, and ignored for allocators and
/// file openers: returning 0 from `malloc` makes the caller dereference NULL,
/// which is never what "pretend this succeeded" means.
#[derive(Clone, Debug)]
pub struct Override {
    pub name: String,
    pub ret: Option<u64>,
}

impl Override {
    fn ret_applies(&self) -> bool {
        !matches!(
            self.name.to_ascii_lowercase().as_str(),
            "malloc"
                | "calloc"
                | "realloc"
                | "valloc"
                | "memalign"
                | "aligned_alloc"
                | "strdup"
                | "strndup"
                | "fopen"
                | "fdopen"
                | "tmpfile"
                | "open"
                | "openat"
        )
    }
}

pub struct Options {
    pub max_insns: u64,
    pub timeout_ms: u64,
    pub vfs: bool,
    pub as_double: bool,
    pub thumb: bool,
    /// Record every executed address, and disassemble the first few.
    pub trace: bool,
    /// Registers to report after the run.
    pub regs: Vec<String>,
    /// Memory to read after the run.
    pub read_ranges: Vec<ReadRange>,
    /// Read this many bytes at the returned pointer. A function that builds a
    /// string or fills a struct answers with an address, and the address alone
    /// says nothing.
    pub read_ret: usize,
    /// Address to import call, replacing whatever the loader wired there.
    pub overrides: HashMap<u64, Override>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_insns: 2_000_000,
            timeout_ms: 10_000,
            vfs: true,
            as_double: false,
            thumb: false,
            trace: false,
            regs: Vec::new(),
            read_ranges: Vec::new(),
            read_ret: 0,
            overrides: HashMap::new(),
        }
    }
}

pub struct Machine {
    pub uc: Uc<'static>,
    pub st: Rc<RefCell<State>>,
    pub loaded: Loaded,
}

impl Machine {
    pub fn new(loaded: Loaded, opts: &Options) -> Result<Self> {
        let vfs = opts.vfs;
        let (ucarch, mode) = match loaded.arch {
            Arch::X86_64 => (UcArch::X86, Mode::LITTLE_ENDIAN | Mode::MODE_64),
            Arch::X86 => (UcArch::X86, Mode::LITTLE_ENDIAN | Mode::MODE_32),
            Arch::Arm => (UcArch::ARM, Mode::LITTLE_ENDIAN | Mode::ARM),
            Arch::Arm64 => (UcArch::ARM64, Mode::LITTLE_ENDIAN),
        };
        let mut uc: Uc<'static> =
            Unicorn::new(ucarch, mode).map_err(|e| anyhow::anyhow!("cannot start unicorn: {e}"))?;

        map_segments(&mut uc, &loaded)?;
        map_region(&mut uc, STUB_BASE, (STUB_SLOTS * STUB_STRIDE).max(0x10_000))?;
        map_region(&mut uc, HEAP_BASE, HEAP_SIZE)?;
        map_region(&mut uc, TLS_BASE, 0x1000)?;

        let stack_top = if loaded.arch.is_64() {
            0x7fff_0000_0000
        } else {
            0x7ff0_0000
        };
        let stack_base = stack_top - STACK_SIZE;
        map_region(&mut uc, stack_base, STACK_SIZE)?;

        let st = Rc::new(RefCell::new(State::new(&loaded, vfs)));
        st.borrow_mut().overrides = opts.overrides.clone();

        // Fill import slots and relocations, creating one stub per unique name.
        let mut stubs: HashMap<String, u64> = HashMap::new();
        for slot in &loaded.import_slots {
            let stub = stub_for(&mut uc, &st, &mut stubs, &slot.name)?;
            write_ptr(&mut uc, loaded.arch, slot.addr, stub)?;
        }
        // An IFUNC slot holds the address of a resolver, and the value it
        // returns is the function to call. That cannot be run yet: the hooks
        // that answer imported calls are installed further down. The slots are
        // zeroed here and filled once the machine is complete.
        let mut ifuncs: Vec<(u64, u64)> = Vec::new();
        for reloc in &loaded.relocs {
            let value = match reloc.kind {
                RelocKind::Relative => {
                    let addend = if reloc.implicit_addend {
                        read_ptr(&uc, loaded.arch, reloc.addr).unwrap_or(0) as i64
                    } else {
                        reloc.addend
                    };
                    loaded.base.wrapping_add(addend as u64)
                }
                RelocKind::Absolute | RelocKind::Slot => {
                    let sym = reloc.sym.as_deref().unwrap_or("");
                    if let Some(addr) = loaded.find_symbol(sym) {
                        if reloc.ifunc {
                            // The symbol's address is the resolver. The slot
                            // has to hold what the resolver returns.
                            ifuncs.push((reloc.addr, addr));
                            0
                        } else {
                            addr.wrapping_add(reloc.addend as u64)
                        }
                    } else if !sym.is_empty() {
                        let stub = stub_for(&mut uc, &st, &mut stubs, sym)?;
                        stub.wrapping_add(reloc.addend as u64)
                    } else {
                        0
                    }
                }
                RelocKind::Ifunc => {
                    let offset = if reloc.implicit_addend {
                        read_ptr(&uc, loaded.arch, reloc.addr).unwrap_or(0) as i64
                    } else {
                        reloc.addend
                    };
                    if offset != 0 {
                        ifuncs.push((reloc.addr, loaded.base.wrapping_add(offset as u64)));
                    }
                    0
                }
            };
            write_ptr(&mut uc, loaded.arch, reloc.addr, value)?;
        }

        // A JNIEnv is always present: it costs a table and costs the guest
        // nothing, and a native method that never touches it is unaffected.
        crate::jni::install(&mut uc, &st, &mut stubs)?;

        // TLS: a real x86-64 function with a stack protector reads fs:0x28.
        // Giving it a mapped base and a canary keeps that read from faulting.
        if loaded.arch == Arch::X86_64 {
            // These two registers only exist in 64-bit mode; writing them in
            // 32-bit mode is a no-op that unicorn warns about loudly.
            let _ = uc.reg_write(RegisterX86::FS_BASE as i32, TLS_BASE);
            let _ = uc.reg_write(RegisterX86::GS_BASE as i32, TLS_BASE);
            let _ = uc.mem_write(TLS_BASE + 0x28, &0xdead_beef_cafe_babeu64.to_le_bytes());
            let _ = uc.mem_write(TLS_BASE + 0x14, &0xdeadbeefu32.to_le_bytes());
        }

        {
            let st2 = Rc::clone(&st);
            let arch = loaded.arch;
            uc.add_code_hook(
                SENTINEL,
                SENTINEL + STUB_SLOTS * STUB_STRIDE,
                move |uc, addr, _| {
                    on_stub(uc, &st2, arch, addr);
                },
            )
            .map_err(|e| anyhow::anyhow!("cannot hook stubs: {e}"))?;
        }
        // The trace and address overrides need to see every instruction, which
        // costs a callback each time — so the hook is only installed when one of
        // them was asked for. Stub addresses are left to `on_stub`: it owns the
        // dispatch there, and two hooks answering one call would answer twice.
        if opts.trace || !opts.overrides.is_empty() {
            let st2 = Rc::clone(&st);
            let arch = loaded.arch;
            uc.add_code_hook(1, 0, move |uc, addr, _| {
                on_any(uc, &st2, arch, addr);
            })
            .map_err(|e| anyhow::anyhow!("cannot hook instructions: {e}"))?;
        }
        {
            let st2 = Rc::clone(&st);
            let arch = loaded.arch;
            uc.add_intr_hook(move |uc, intno| on_intr(uc, &st2, arch, intno))
                .map_err(|e| anyhow::anyhow!("cannot hook interrupts: {e}"))?;
        }
        {
            let st2 = Rc::clone(&st);
            let arch = loaded.arch;
            uc.add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, move |uc| on_syscall(uc, &st2, arch))
                .map_err(|e| anyhow::anyhow!("cannot hook syscall: {e}"))?;
        }
        {
            // Unicorn's error says only "read from unmapped memory", which is
            // useless without the address. The hook sees it, records it, and
            // returns false so the engine still raises the error and stops.
            let st2 = Rc::clone(&st);
            uc.add_mem_hook(
                HookType::MEM_READ_UNMAPPED
                    | HookType::MEM_WRITE_UNMAPPED
                    | HookType::MEM_FETCH_UNMAPPED,
                1,
                0,
                move |uc, kind, address, size, _| {
                    let mut state = st2.borrow_mut();
                    if state.fault.is_none() {
                        state.fault = Some(Fault {
                            access: match kind {
                                MemType::WRITE_UNMAPPED => "write",
                                MemType::FETCH_UNMAPPED => "fetch",
                                _ => "read",
                            },
                            address,
                            size: size as u64,
                            pc: uc.reg_read(pc_reg_id(state.arch)).unwrap_or(0),
                        });
                    }
                    false
                },
            )
            .map_err(|e| anyhow::anyhow!("cannot hook memory: {e}"))?;
        }

        let mut machine = Machine { uc, st, loaded };
        for (slot, resolver) in ifuncs {
            machine.resolve_ifunc(slot, resolver)?;
        }
        Ok(machine)
    }

    /// Call an IFUNC resolver and store the function it chose.
    ///
    /// A resolver takes no arguments and returns a pointer; it runs before the
    /// function the caller asked for, so its effect on the shared state (the
    /// stop reason above all) is undone afterwards.
    fn resolve_ifunc(&mut self, slot: u64, resolver: u64) -> Result<()> {
        let stack_top = if self.loaded.arch.is_64() {
            0x7fff_0000_0000
        } else {
            0x7ff0_0000
        };
        self.setup_call(resolver, None, &[], stack_top, false)?;
        let started = self.uc.emu_start(resolver, 0, 5_000_000, 0);
        let arch = self.loaded.arch;
        let value = read_return(&self.uc, arch);
        let mut state = self.st.borrow_mut();
        state.stop = Stop::Running;
        if let Err(err) = started {
            // A resolver that fails is not fatal: the slot stays zero, and the
            // call through it will report an unmapped fetch, which is a better
            // clue than "the loader gave up".
            state
                .notes
                .push(format!("ifunc resolver at 0x{resolver:x}: {err}"));
            return Ok(());
        }
        drop(state);
        write_ptr(&mut self.uc, arch, slot, value)?;
        Ok(())
    }

    pub fn run(
        &mut self,
        target: u64,
        symbol: Option<&str>,
        args: &[Arg],
        opts: &Options,
    ) -> Result<Report> {
        let stack_top = if self.loaded.arch.is_64() {
            0x7fff_0000_0000
        } else {
            0x7ff0_0000
        };
        self.setup_call(target, symbol, args, stack_top, opts.thumb)?;

        self.st.borrow_mut().start = Instant::now();
        let begin = Instant::now();
        let timeout_us = opts.timeout_ms.saturating_mul(1000);
        let count = if opts.max_insns == 0 {
            0
        } else {
            opts.max_insns as usize
        };
        let result = self.uc.emu_start(target, 0, timeout_us, count);

        let timed_out = self
            .uc
            .query(Query::TIMEOUT)
            .map(|v| v != 0)
            .unwrap_or(false);
        let mut state = self.st.borrow_mut();
        if state.stop == Stop::Running {
            state.stop = match result {
                Ok(()) => {
                    if timed_out {
                        Stop::Timeout
                    } else {
                        Stop::InsnLimit
                    }
                }
                Err(e) => {
                    if timed_out {
                        Stop::Timeout
                    } else {
                        state
                            .notes
                            .push(format!("emulation stopped: {}", describe_err(e)));
                        Stop::Fault
                    }
                }
            };
        }
        drop(state);

        let arch = self.loaded.arch;
        let ret = read_return(&self.uc, arch);
        let ret_f64 = if opts.as_double {
            read_double(&self.uc, arch)
        } else {
            None
        };
        let state = self.st.borrow();
        let stop = match state.stop {
            Stop::Returned => "returned",
            Stop::Exited(_) => "exited",
            Stop::InsnLimit => "instruction limit",
            Stop::Timeout => "timeout",
            Stop::Fault => "fault",
            Stop::Running => "running",
        };
        // Read the extras while the machine is still alive: after this the
        // memory is gone.
        let regs = read_regs(&self.uc, arch, &opts.regs);
        let mut reads = read_out(&self.uc, &opts.read_ranges);
        if opts.read_ret > 0 && ret != 0 {
            reads.extend(read_out(
                &self.uc,
                &[ReadRange {
                    addr: ret,
                    size: opts.read_ret,
                    label: "ret".to_string(),
                }],
            ));
        }
        let disasm = if opts.trace {
            disassemble(&self.uc, arch, &state.trace, TRACE_SHOWN, opts.thumb)
        } else {
            Vec::new()
        };
        Ok(Report {
            ok: state.stop == Stop::Returned,
            arch: arch.name().to_string(),
            platform: self.loaded.platform.name().to_string(),
            symbol: symbol.map(str::to_string),
            address: format!("0x{target:x}"),
            stop: stop.to_string(),
            ret: ReturnValue {
                hex: format!("0x{ret:x}"),
                i64: ret as i64,
                u64: ret,
                f64: ret_f64,
            },
            output: state.output.clone(),
            calls: state
                .calls
                .iter()
                .map(|(n, c)| CallCount {
                    name: n.clone(),
                    count: *c,
                })
                .collect(),
            unimplemented: state.unknown.clone(),
            files: state.files.iter().map(|f| f.path.clone()).collect(),
            notes: state.notes.clone(),
            fault: state.fault.clone(),
            regs,
            reads,
            disasm,
            overrides: state.override_notes.clone(),
            elapsed_ms: begin.elapsed().as_millis() as u64,
        })
    }

    fn setup_call(
        &mut self,
        target: u64,
        symbol: Option<&str>,
        args: &[Arg],
        stack_top: u64,
        thumb: bool,
    ) -> Result<()> {
        let arch = self.loaded.arch;
        let platform = self.loaded.platform;

        // Strings live in the heap; replace them with their addresses. From
        // here on an argument knows whether it is an integer or a double,
        // because the two go to different registers.
        let mut resolved: Vec<Slot> = Vec::with_capacity(args.len());
        for arg in args {
            match arg {
                Arg::Num(n) => resolved.push(Slot::Int(*n)),
                Arg::Float(f) => resolved.push(Slot::Float(*f)),
                Arg::Env => {
                    let env = self.st.borrow().jni_env;
                    if env == 0 {
                        bail!("this build has no JNIEnv to pass");
                    }
                    resolved.push(Slot::Int(env));
                }
                Arg::Str(s) => {
                    let addr = {
                        let mut st = self.st.borrow_mut();
                        st.alloc(&mut self.uc, s.len() + 1)
                    };
                    if addr == 0 {
                        bail!("out of emulated heap while placing an argument");
                    }
                    self.uc
                        .mem_write(addr, s.as_bytes())
                        .and_then(|_| self.uc.mem_write(addr + s.len() as u64, &[0]))
                        .map_err(|e| anyhow::anyhow!("cannot write argument: {e}"))?;
                    resolved.push(Slot::Int(addr));
                }
            }
        }

        // A native method named the JNI way always takes the environment
        // first, and callers rarely bother to spell it out. Doing it by name
        // is safe: an ordinary function called with a literal zero keeps its
        // zero, so `t_abs(0)` still returns 0.
        if crate::jni::wants_env(symbol) {
            let env = self.st.borrow().jni_env;
            if env != 0 {
                match resolved.first_mut() {
                    None => resolved.push(Slot::Int(env)),
                    Some(Slot::Int(value)) if *value == 0 => *value = env,
                    Some(_) => {}
                }
            }
        }

        let base = stack_top - 0x1000;
        match arch {
            Arch::X86_64 => {
                let win = platform == Platform::Windows;
                let regs: [RegisterX86; 6] = if win {
                    [
                        RegisterX86::RCX,
                        RegisterX86::RDX,
                        RegisterX86::R8,
                        RegisterX86::R9,
                        RegisterX86::RAX,
                        RegisterX86::RAX,
                    ]
                } else {
                    [
                        RegisterX86::RDI,
                        RegisterX86::RSI,
                        RegisterX86::RDX,
                        RegisterX86::RCX,
                        RegisterX86::R8,
                        RegisterX86::R9,
                    ]
                };
                let nregs = if win { 4 } else { 6 };
                let shadow = if win { 0x20 } else { 0 };
                let rsp = base - 8;
                write_ptr(&mut self.uc, arch, rsp, SENTINEL)?;
                if win {
                    // Shadow space for the four register arguments.
                    let zeros = [0u8; 0x20];
                    let _ = self.uc.mem_write(base, &zeros);
                }
                let (mut int_i, mut float_i, mut stack_i) = (0usize, 0usize, 0usize);
                for slot in &resolved {
                    match *slot {
                        Slot::Int(value) => {
                            if int_i < nregs {
                                self.uc.reg_write(regs[int_i], value).map_err(|e| {
                                    anyhow::anyhow!("cannot set argument register: {e}")
                                })?;
                            } else {
                                write_ptr(
                                    &mut self.uc,
                                    arch,
                                    base + shadow + 8 * stack_i as u64,
                                    value,
                                )?;
                                stack_i += 1;
                            }
                            int_i += 1;
                        }
                        Slot::Float(value) => {
                            if float_i < 8 {
                                self.uc
                                    .reg_write_long(
                                        RegisterX86::XMM0 as i32 + float_i as i32,
                                        &value.to_le_bytes(),
                                    )
                                    .map_err(|e| {
                                        anyhow::anyhow!("cannot set float argument: {e}")
                                    })?;
                            } else {
                                let addr = base + shadow + 8 * stack_i as u64;
                                write_bytes(&mut self.uc, addr, &value.to_le_bytes());
                                stack_i += 1;
                            }
                            float_i += 1;
                        }
                    }
                }
                // SysV variadic ABI: al = number of vector registers used.
                let _ = self.uc.reg_write(RegisterX86::RAX, 0);
                self.uc
                    .reg_write(RegisterX86::RSP, rsp)
                    .map_err(|e| anyhow::anyhow!("cannot set stack pointer: {e}"))?;
                self.uc
                    .reg_write(RegisterX86::RIP, target)
                    .map_err(|e| anyhow::anyhow!("cannot set program counter: {e}"))?;
            }
            Arch::X86 => {
                // Everything goes on the stack, in order; a double takes two
                // slots and is written whole.
                let esp = base - 4;
                write_ptr(&mut self.uc, arch, esp, SENTINEL)?;
                let mut offset = 0u64;
                for slot in &resolved {
                    match *slot {
                        Slot::Int(value) => {
                            write_ptr(&mut self.uc, arch, base + offset, value)?;
                            offset += 4;
                        }
                        Slot::Float(value) => {
                            write_bytes(&mut self.uc, base + offset, &value.to_le_bytes());
                            offset += 8;
                        }
                    }
                }
                self.uc
                    .reg_write(RegisterX86::ESP, esp)
                    .map_err(|e| anyhow::anyhow!("cannot set stack pointer: {e}"))?;
                self.uc
                    .reg_write(RegisterX86::EIP, target)
                    .map_err(|e| anyhow::anyhow!("cannot set program counter: {e}"))?;
            }
            Arch::Arm64 => {
                let sp = base & !0xf;
                let regs = [
                    RegisterARM64::X0,
                    RegisterARM64::X1,
                    RegisterARM64::X2,
                    RegisterARM64::X3,
                    RegisterARM64::X4,
                    RegisterARM64::X5,
                    RegisterARM64::X6,
                    RegisterARM64::X7,
                ];
                let (mut int_i, mut float_i, mut stack_i) = (0usize, 0usize, 0usize);
                for slot in &resolved {
                    match *slot {
                        Slot::Int(value) => {
                            if int_i < regs.len() {
                                self.uc.reg_write(regs[int_i], value).map_err(|e| {
                                    anyhow::anyhow!("cannot set argument register: {e}")
                                })?;
                            } else {
                                write_ptr(&mut self.uc, arch, sp + 8 * stack_i as u64, value)?;
                                stack_i += 1;
                            }
                            int_i += 1;
                        }
                        Slot::Float(value) => {
                            if float_i < 8 {
                                let mut quad = [0u8; 16];
                                quad[..8].copy_from_slice(&value.to_le_bytes());
                                self.uc
                                    .reg_write_long(
                                        RegisterARM64::Q0 as i32 + float_i as i32,
                                        &quad,
                                    )
                                    .map_err(|e| {
                                        anyhow::anyhow!("cannot set float argument: {e}")
                                    })?;
                            } else {
                                write_bytes(
                                    &mut self.uc,
                                    sp + 8 * stack_i as u64,
                                    &value.to_le_bytes(),
                                );
                                stack_i += 1;
                            }
                            float_i += 1;
                        }
                    }
                }
                self.uc
                    .reg_write(RegisterARM64::SP, sp)
                    .map_err(|e| anyhow::anyhow!("cannot set stack pointer: {e}"))?;
                self.uc
                    .reg_write(RegisterARM64::X30, SENTINEL)
                    .map_err(|e| anyhow::anyhow!("cannot set link register: {e}"))?;
                let pc = if thumb { target | 1 } else { target };
                self.uc
                    .reg_write(RegisterARM64::PC, pc)
                    .map_err(|e| anyhow::anyhow!("cannot set program counter: {e}"))?;
            }
            Arch::Arm => {
                let sp = base & !0x7;
                let regs = [
                    RegisterARM::R0,
                    RegisterARM::R1,
                    RegisterARM::R2,
                    RegisterARM::R3,
                ];
                let (mut int_i, mut float_i, mut stack_i) = (0usize, 0usize, 0usize);
                for slot in &resolved {
                    match *slot {
                        Slot::Int(value) => {
                            if int_i < regs.len() {
                                self.uc.reg_write(regs[int_i], value).map_err(|e| {
                                    anyhow::anyhow!("cannot set argument register: {e}")
                                })?;
                            } else {
                                write_ptr(&mut self.uc, arch, sp + 4 * stack_i as u64, value)?;
                                stack_i += 1;
                            }
                            int_i += 1;
                        }
                        Slot::Float(value) => {
                            if float_i < 16 {
                                self.uc
                                    .reg_write(
                                        RegisterARM::D0 as i32 + float_i as i32,
                                        value.to_bits(),
                                    )
                                    .map_err(|e| {
                                        anyhow::anyhow!("cannot set float argument: {e}")
                                    })?;
                            } else {
                                // The stack keeps doubles 8-byte aligned.
                                let addr = (sp + 4 * stack_i as u64).next_multiple_of(8);
                                write_bytes(&mut self.uc, addr, &value.to_le_bytes());
                                stack_i += 2;
                            }
                            float_i += 1;
                        }
                    }
                }
                self.uc
                    .reg_write(RegisterARM::SP, sp)
                    .map_err(|e| anyhow::anyhow!("cannot set stack pointer: {e}"))?;
                self.uc
                    .reg_write(RegisterARM::LR, SENTINEL)
                    .map_err(|e| anyhow::anyhow!("cannot set link register: {e}"))?;
                let pc = if thumb { target | 1 } else { target };
                self.uc
                    .reg_write(RegisterARM::PC, pc)
                    .map_err(|e| anyhow::anyhow!("cannot set program counter: {e}"))?;
            }
        }
        Ok(())
    }
}

pub(crate) fn stub_for(
    uc: &mut Uc<'_>,
    st: &Rc<RefCell<State>>,
    stubs: &mut HashMap<String, u64>,
    name: &str,
) -> Result<u64> {
    if let Some(addr) = stubs.get(name) {
        return Ok(*addr);
    }
    let mut state = st.borrow_mut();
    let index = state.import_names.len() as u64;
    if index >= STUB_SLOTS {
        bail!("too many imported symbols ({index})");
    }
    let addr = STUB_BASE + index * STUB_STRIDE;
    state.import_names.push(name.to_string());
    state.name_slots.insert(name.to_string(), index as usize);
    stubs.insert(name.to_string(), addr);
    drop(state);
    // A stub is never executed: the code hook redirects before the first
    // instruction. Still make the page contain something deterministic.
    let _ = uc.mem_write(addr, &[0xf4; 8]);
    Ok(addr)
}

fn map_region(uc: &mut Uc<'_>, addr: u64, size: u64) -> Result<()> {
    let start = addr & !0xfff;
    let end = (addr + size + 0xfff) & !0xfff;
    uc.mem_map(start, end - start, Prot::ALL)
        .map_err(|e| anyhow::anyhow!("cannot map {start:#x}..{end:#x}: {e}"))
}

fn map_segments(uc: &mut Uc<'_>, loaded: &Loaded) -> Result<()> {
    let mut ranges: Vec<(u64, u64)> = loaded
        .segments
        .iter()
        .filter(|s| s.mem_size > 0)
        .map(|s| (s.addr & !0xfff, (s.addr + s.mem_size + 0xfff) & !0xfff))
        .collect();
    ranges.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some((_, prev_end)) if start <= *prev_end => *prev_end = (*prev_end).max(end),
            _ => merged.push((start, end)),
        }
    }
    for (start, end) in merged {
        if end - start > 0x4000_0000 {
            bail!("refusing to map a segment larger than 1 GiB ({start:#x}..{end:#x})");
        }
        uc.mem_map(start, end - start, Prot::ALL)
            .map_err(|e| anyhow::anyhow!("cannot map {start:#x}..{end:#x}: {e}"))?;
    }
    for seg in &loaded.segments {
        if seg.data.is_empty() {
            continue;
        }
        uc.mem_write(seg.addr, &seg.data)
            .with_context(|| format!("cannot write segment at {:#x}", seg.addr))?;
    }
    Ok(())
}

//
// ABI helpers
//

pub fn arg_reg_ids(arch: Arch, platform: Platform) -> Vec<i32> {
    match arch {
        Arch::X86_64 => {
            if platform == Platform::Windows {
                vec![
                    RegisterX86::RCX as i32,
                    RegisterX86::RDX as i32,
                    RegisterX86::R8 as i32,
                    RegisterX86::R9 as i32,
                ]
            } else {
                vec![
                    RegisterX86::RDI as i32,
                    RegisterX86::RSI as i32,
                    RegisterX86::RDX as i32,
                    RegisterX86::RCX as i32,
                    RegisterX86::R8 as i32,
                    RegisterX86::R9 as i32,
                ]
            }
        }
        Arch::X86 => Vec::new(),
        Arch::Arm => vec![
            RegisterARM::R0 as i32,
            RegisterARM::R1 as i32,
            RegisterARM::R2 as i32,
            RegisterARM::R3 as i32,
        ],
        Arch::Arm64 => vec![
            RegisterARM64::X0 as i32,
            RegisterARM64::X1 as i32,
            RegisterARM64::X2 as i32,
            RegisterARM64::X3 as i32,
            RegisterARM64::X4 as i32,
            RegisterARM64::X5 as i32,
            RegisterARM64::X6 as i32,
            RegisterARM64::X7 as i32,
        ],
    }
}

pub fn ret_reg_id(arch: Arch) -> i32 {
    match arch {
        Arch::X86_64 => RegisterX86::RAX as i32,
        Arch::X86 => RegisterX86::EAX as i32,
        Arch::Arm => RegisterARM::R0 as i32,
        Arch::Arm64 => RegisterARM64::X0 as i32,
    }
}

pub fn sp_reg_id(arch: Arch) -> i32 {
    match arch {
        Arch::X86_64 => RegisterX86::RSP as i32,
        Arch::X86 => RegisterX86::ESP as i32,
        Arch::Arm => RegisterARM::SP as i32,
        Arch::Arm64 => RegisterARM64::SP as i32,
    }
}

fn pc_reg_id(arch: Arch) -> i32 {
    match arch {
        Arch::X86_64 => RegisterX86::RIP as i32,
        Arch::X86 => RegisterX86::EIP as i32,
        Arch::Arm => RegisterARM::PC as i32,
        Arch::Arm64 => RegisterARM64::PC as i32,
    }
}

/// Stack offset of the first stack argument, relative to the stack pointer.
pub fn stack_arg_base(arch: Arch, platform: Platform) -> u64 {
    match arch {
        Arch::X86_64 => {
            if platform == Platform::Windows {
                0x28
            } else {
                8
            }
        }
        Arch::X86 => 4,
        Arch::Arm | Arch::Arm64 => 0,
    }
}

pub fn read_return(uc: &Uc<'_>, arch: Arch) -> u64 {
    uc.reg_read(ret_reg_id(arch)).unwrap_or(0)
}

pub fn write_return(uc: &mut Uc<'_>, arch: Arch, value: u64) {
    let _ = uc.reg_write(ret_reg_id(arch), value);
}

fn read_double(uc: &Uc<'_>, arch: Arch) -> Option<f64> {
    // The 32-bit x87 stack is not modelled, so there is nothing to read.
    if arch == Arch::X86 {
        return None;
    }
    Some(float_arg(uc, arch, 0, false))
}

/// A floating-point argument, by ABI.
///
/// Doubles and floats live in different registers than the integer arguments,
/// so `arg_at` cannot reach them: x86-64 uses `xmm0..7` (a float in the low
/// half), AArch64 uses `d0..7` (`s0..7` for a float), ARM32 the same. A bare
/// Unicorn has no libm behind the import, which is why the math functions are
/// answered here at all.
pub(crate) fn float_arg(uc: &Uc<'_>, arch: Arch, index: usize, single: bool) -> f64 {
    match arch {
        Arch::X86_64 => {
            let bytes = uc
                .reg_read_long(RegisterX86::XMM0 as i32 + index as i32)
                .unwrap_or_default();
            if bytes.len() < 8 {
                return 0.0;
            }
            if single {
                f32::from_le_bytes(bytes[..4].try_into().unwrap()) as f64
            } else {
                f64::from_le_bytes(bytes[..8].try_into().unwrap())
            }
        }
        Arch::Arm64 => {
            // `reg_read_long` in the binding only sizes Q/V registers, so a
            // `d` register is read through the `q` that contains it.
            let bytes = uc
                .reg_read_long(RegisterARM64::Q0 as i32 + index as i32)
                .unwrap_or_default();
            if bytes.len() < 8 {
                return 0.0;
            }
            if single {
                f32::from_le_bytes(bytes[..4].try_into().unwrap()) as f64
            } else {
                f64::from_le_bytes(bytes[..8].try_into().unwrap())
            }
        }
        Arch::Arm => {
            // ...and for 32-bit ARM it does not size anything at all, so the
            // plain 64-bit read is used: d0..d31 and s0..s31 are each its own
            // register, and the low half is what a single occupies.
            let reg = if single {
                RegisterARM::S0 as i32 + index as i32
            } else {
                RegisterARM::D0 as i32 + index as i32
            };
            match uc.reg_read(reg) {
                Ok(bits) if single => f32::from_bits(bits as u32) as f64,
                Ok(bits) => f64::from_bits(bits),
                Err(_) => 0.0,
            }
        }
        // 32-bit x86 passes floating point on the stack through x87, which is
        // a different machine than the one being modelled here.
        Arch::X86 => 0.0,
    }
}

/// Put a floating-point result where the ABI expects it.
pub(crate) fn set_float_return(uc: &mut Uc<'_>, arch: Arch, value: f64) {
    let _ = match arch {
        Arch::X86_64 => uc.reg_write_long(RegisterX86::XMM0 as i32, &value.to_le_bytes()),
        Arch::Arm64 => {
            let mut quad = [0u8; 16];
            quad[..8].copy_from_slice(&value.to_le_bytes());
            uc.reg_write_long(RegisterARM64::Q0 as i32, &quad)
        }
        Arch::Arm => uc.reg_write(RegisterARM::D0 as i32, value.to_bits()),
        Arch::X86 => Ok(()),
    };
}

/// Register name to unicorn id, per architecture. Names follow what a caller
/// would type after looking at the disassembly (`rax`, `x0`, `r7`), not the
/// emulator's internal numbering.
fn reg_id(arch: Arch, name: &str) -> Option<i32> {
    let name = name.trim().trim_start_matches('%').to_ascii_lowercase();
    match arch {
        Arch::X86_64 => {
            let id = match name.as_str() {
                "rax" => RegisterX86::RAX,
                "rbx" => RegisterX86::RBX,
                "rcx" => RegisterX86::RCX,
                "rdx" => RegisterX86::RDX,
                "rsi" => RegisterX86::RSI,
                "rdi" => RegisterX86::RDI,
                "rbp" => RegisterX86::RBP,
                "rsp" => RegisterX86::RSP,
                "rip" | "pc" => RegisterX86::RIP,
                "eflags" => RegisterX86::EFLAGS,
                _ => {
                    let n = name.strip_prefix('r')?.parse::<u8>().ok()?;
                    let base = RegisterX86::R8 as i32;
                    if !(8..=15).contains(&n) {
                        return None;
                    }
                    return Some(base + (n as i32 - 8));
                }
            };
            Some(id as i32)
        }
        Arch::X86 => {
            let id = match name.as_str() {
                "eax" => RegisterX86::EAX,
                "ebx" => RegisterX86::EBX,
                "ecx" => RegisterX86::ECX,
                "edx" => RegisterX86::EDX,
                "esi" => RegisterX86::ESI,
                "edi" => RegisterX86::EDI,
                "ebp" => RegisterX86::EBP,
                "esp" => RegisterX86::ESP,
                "eip" | "pc" => RegisterX86::EIP,
                "eflags" => RegisterX86::EFLAGS,
                _ => return None,
            };
            Some(id as i32)
        }
        Arch::Arm64 => {
            let id = match name.as_str() {
                "sp" => RegisterARM64::SP,
                "pc" => RegisterARM64::PC,
                "fp" | "x29" => RegisterARM64::X29,
                "lr" | "x30" => RegisterARM64::X30,
                _ => {
                    let n = name.strip_prefix('x')?.parse::<u8>().ok()?;
                    if n > 28 {
                        return None;
                    }
                    return Some((RegisterARM64::X0 as i32) + n as i32);
                }
            };
            Some(id as i32)
        }
        Arch::Arm => {
            let id = match name.as_str() {
                "sp" | "r13" => RegisterARM::SP,
                "lr" | "r14" => RegisterARM::LR,
                "pc" | "r15" => RegisterARM::PC,
                "cpsr" => RegisterARM::CPSR,
                _ => {
                    let n = name.strip_prefix('r')?.parse::<u8>().ok()?;
                    if n > 12 {
                        return None;
                    }
                    return Some((RegisterARM::R0 as i32) + n as i32);
                }
            };
            Some(id as i32)
        }
    }
}

/// The registers the caller asked for, in the order they asked, as hex.
fn read_regs(
    uc: &Uc<'_>,
    arch: Arch,
    wanted: &[String],
) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for name in wanted {
        let shown = name.trim().trim_start_matches('%').to_ascii_lowercase();
        if shown.is_empty() {
            continue;
        }
        if let Some(id) = reg_id(arch, &shown) {
            if let Ok(value) = uc.reg_read(id) {
                out.insert(shown, format!("0x{value:x}"));
            }
        }
    }
    out
}

/// Read memory into a fresh buffer. `Unicorn::mem_read` fills a caller buffer,
/// which is awkward when the result is what you wanted.
fn read_mem(uc: &Uc<'_>, addr: u64, size: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; size];
    uc.mem_read(addr, &mut buf)
        .map_err(|e| format!("{e:?}").to_lowercase())?;
    Ok(buf)
}

/// Read the requested ranges back. A range that is not mapped is reported, not
/// turned into a failure: the caller's guess is checked, not obeyed.
fn read_out(uc: &Uc<'_>, wanted: &[ReadRange]) -> Vec<Readout> {
    let mut out = Vec::with_capacity(wanted.len());
    for range in wanted {
        let size = range.size.min(1 << 20);
        match read_mem(uc, range.addr, size) {
            Ok(bytes) => out.push(Readout {
                label: range.label.clone(),
                addr: format!("0x{:x}", range.addr),
                size,
                hex: Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                ascii: Some(
                    bytes
                        .iter()
                        .map(|b| {
                            if (0x20..0x7f).contains(b) {
                                *b as char
                            } else {
                                '.'
                            }
                        })
                        .collect(),
                ),
                error: None,
            }),
            Err(err) => out.push(Readout {
                label: range.label.clone(),
                addr: format!("0x{:x}", range.addr),
                size,
                hex: None,
                ascii: None,
                error: Some(format!("{err:?}").to_lowercase()),
            }),
        }
    }
    out
}

/// Disassemble the head of the trace, so "it stopped at 0x401123" can be read
/// as instructions instead of numbers.
fn disassemble(uc: &Uc<'_>, arch: Arch, trace: &[u64], shown: usize, thumb: bool) -> Vec<String> {
    use capstone::prelude::*;

    let built = match arch {
        Arch::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build(),
        Arch::X86 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .build(),
        Arch::Arm64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build(),
        // The same CPU runs both encodings, so which one the trace is in is a
        // property of the target, not of the file.
        Arch::Arm if thumb => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .build(),
        Arch::Arm => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build(),
    };
    let Ok(cs) = built else {
        // No capstone is not a reason to print nothing.
        return trace
            .iter()
            .take(shown)
            .map(|a| format!("0x{a:x}"))
            .collect();
    };

    let mut out = Vec::new();
    for &addr in trace.iter().take(shown) {
        let Ok(code) = read_mem(uc, addr, 16) else {
            out.push(format!("0x{addr:x}  <not mapped>"));
            continue;
        };
        let decoded = cs.disasm_count(&code, addr, 1);
        let line = decoded
            .ok()
            .and_then(|insns| insns.iter().next().map(|ins| line_for(ins, addr)));
        out.push(line.unwrap_or_else(|| format!("0x{addr:x}  <undecodable>")));
    }
    out
}

fn line_for(ins: &capstone::Insn<'_>, addr: u64) -> String {
    format!(
        "0x{addr:x}  {} {}",
        ins.mnemonic().unwrap_or("?"),
        ins.op_str().unwrap_or("")
    )
    .trim_end()
    .to_string()
}

fn describe_err(e: uc_error) -> String {
    match e {
        uc_error::READ_UNMAPPED => "read from unmapped memory".into(),
        uc_error::WRITE_UNMAPPED => "write to unmapped memory".into(),
        uc_error::FETCH_UNMAPPED => "execution left mapped memory".into(),
        uc_error::INSN_INVALID => "invalid instruction".into(),
        uc_error::EXCEPTION => "cpu exception".into(),
        other => format!("{other:?}").to_lowercase(),
    }
}

//
// Hooks
//

fn on_stub(uc: &mut Uc<'_>, st: &Rc<RefCell<State>>, arch: Arch, addr: u64) {
    if addr < STUB_BASE {
        return;
    }
    let index = ((addr - STUB_BASE) / STUB_STRIDE) as usize;
    let mut state = st.borrow_mut();
    if index == 0 {
        state.ret = read_return(uc, arch);
        state.stop = Stop::Returned;
        let _ = uc.emu_stop();
        return;
    }
    // A caller-supplied override names the import that should answer here,
    // which is how a static binary (no import table to rewrite) gets told what
    // an address does.
    let override_here = state.overrides.get(&addr).cloned();
    let name = match &override_here {
        Some(over) => over.name.clone(),
        None => state.import_names.get(index).cloned().unwrap_or_default(),
    };
    // The prefix keeps JNI entries out of the import namespace; the report
    // reads better without it.
    let shown = name.strip_prefix("JNI:").unwrap_or(&name).to_string();
    state.count_call(&shown);
    let mut value = imports::call(uc, &mut state, &name);
    if state.halted.is_some() {
        return;
    }
    if let Some(over) = &override_here {
        value = apply_override(&mut state, over, value);
    }
    write_return(uc, arch, value);
    return_to_caller(uc, arch, &mut state);
}

/// Answer an instruction-by-instruction hook: record the trace and, outside the
/// stub page, dispatch any address the caller overrode.
fn on_any(uc: &mut Uc<'_>, st: &Rc<RefCell<State>>, arch: Arch, addr: u64) {
    let mut state = st.borrow_mut();
    if state.trace.len() < TRACE_KEEP {
        state.trace.push(addr);
    }
    // `on_stub` owns the stub page; answering here too would call the import
    // twice for one instruction.
    if (STUB_BASE..STUB_BASE + STUB_SLOTS * STUB_STRIDE).contains(&addr) {
        return;
    }
    let Some(over) = state.overrides.get(&addr).cloned() else {
        return;
    };

    let shown = over
        .name
        .strip_prefix("JNI:")
        .unwrap_or(&over.name)
        .to_string();
    state.count_call(&shown);
    let value = imports::call(uc, &mut state, &over.name);
    if state.halted.is_some() {
        return;
    }
    let value = apply_override(&mut state, &over, value);
    write_return(uc, arch, value);
    return_to_caller(uc, arch, &mut state);
}

/// Hand back the caller's value when they gave one, unless the stub has to
/// return something usable (a buffer, a file handle).
fn apply_override(state: &mut State, over: &Override, value: u64) -> u64 {
    match (over.ret, over.ret_applies()) {
        (Some(ret), true) => {
            state
                .override_notes
                .push(format!("{} -> {ret:#x} (forced)", over.name));
            ret
        }
        (Some(_), false) => {
            state.override_notes.push(format!(
                "{} keeps its own {value:#x}: a forced value here would be an unusable pointer",
                over.name
            ));
            value
        }
        (None, _) => value,
    }
}

fn return_to_caller(uc: &mut Uc<'_>, arch: Arch, state: &mut State) {
    match arch {
        Arch::X86_64 | Arch::X86 => {
            let sp = uc.reg_read(sp_reg_id(arch)).unwrap_or(0);
            let Some(ret) = read_ptr(uc, arch, sp) else {
                state.notes.push("return address was unreadable".into());
                state.stop = Stop::Fault;
                let _ = uc.emu_stop();
                return;
            };
            let _ = uc.reg_write(sp_reg_id(arch), sp + arch.ptr_size());
            let _ = uc.reg_write(pc_reg_id(arch), ret);
        }
        Arch::Arm => {
            let lr = uc.reg_read(RegisterARM::LR).unwrap_or(SENTINEL);
            let _ = uc.reg_write(RegisterARM::PC, lr);
        }
        Arch::Arm64 => {
            let lr = uc.reg_read(RegisterARM64::X30).unwrap_or(SENTINEL);
            let _ = uc.reg_write(RegisterARM64::PC, lr);
        }
    }
}

fn on_intr(uc: &mut Uc<'_>, st: &Rc<RefCell<State>>, arch: Arch, intno: u32) {
    let mut state = st.borrow_mut();
    let handled = crate::syscalls::interrupt(uc, &mut state, arch, intno);
    if !handled {
        state.notes.push(format!("unhandled interrupt {intno:#x}"));
    }
    if state.halted.is_some() {
        return;
    }
    // ARM `svc` is a call into the kernel: the instruction after it continues.
    if matches!(arch, Arch::Arm | Arch::Arm64) {
        let pc = uc.reg_read(pc_reg_id(arch)).unwrap_or(0);
        // `svc` is four bytes on both ARM and AArch64.
        let _ = uc.reg_write(pc_reg_id(arch), pc + 4);
    }
}

fn on_syscall(uc: &mut Uc<'_>, st: &Rc<RefCell<State>>, arch: Arch) {
    let mut state = st.borrow_mut();
    crate::syscalls::x86_syscall(uc, &mut state, arch);
}

//
// Memory helpers, small enough to sit next to the ABI that uses them.
//

pub fn read_bytes(uc: &Uc<'_>, addr: u64, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    uc.mem_read_as_vec(addr, len).ok()
}

pub fn write_bytes(uc: &mut Uc<'_>, addr: u64, data: &[u8]) -> bool {
    uc.mem_write(addr, data).is_ok()
}

pub fn read_ptr(uc: &Uc<'_>, arch: Arch, addr: u64) -> Option<u64> {
    match arch.ptr_size() {
        8 => read_bytes(uc, addr, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())),
        _ => read_bytes(uc, addr, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64),
    }
}

pub fn write_ptr(uc: &mut Uc<'_>, arch: Arch, addr: u64, value: u64) -> Result<()> {
    if arch.ptr_size() == 8 {
        write_bytes(uc, addr, &value.to_le_bytes());
    } else {
        write_bytes(uc, addr, &(value as u32).to_le_bytes());
    }
    Ok(())
}

pub fn write_u32(uc: &mut Uc<'_>, addr: u64, value: u32) -> bool {
    write_bytes(uc, addr, &value.to_le_bytes())
}

pub fn read_cstr(uc: &Uc<'_>, addr: u64, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut off = 0u64;
    while out.len() < max {
        let want = 64.min(max - out.len());
        match read_bytes(uc, addr + off, want) {
            Some(chunk) => {
                if let Some(pos) = chunk.iter().position(|c| *c == 0) {
                    out.extend_from_slice(&chunk[..pos]);
                    break;
                }
                off += want as u64;
                out.extend_from_slice(&chunk);
            }
            None => {
                // Fall back to one byte at a time near a page boundary.
                let mut progressed = false;
                for i in 0..want {
                    match read_bytes(uc, addr + off + i as u64, 1) {
                        Some(b) if !b.is_empty() => {
                            if b[0] == 0 {
                                return out;
                            }
                            out.push(b[0]);
                            progressed = true;
                        }
                        _ => return out,
                    }
                }
                if !progressed {
                    break;
                }
                off += want as u64;
            }
        }
    }
    out
}

pub fn read_cstr_string(uc: &Uc<'_>, addr: u64, max: usize) -> String {
    String::from_utf8_lossy(&read_cstr(uc, addr, max)).to_string()
}

/// The ABI view of the arguments of the function currently being emulated.
pub struct VarArgs<'a, 'u> {
    uc: &'a Uc<'u>,
    arch: Arch,
    regs: Vec<i32>,
    base: u64,
    next: usize,
    float_next: usize,
}

impl<'a, 'u> VarArgs<'a, 'u> {
    pub fn new(uc: &'a Uc<'u>, arch: Arch, platform: Platform) -> Self {
        let sp = uc.reg_read(sp_reg_id(arch)).unwrap_or(0);
        VarArgs {
            uc,
            arch,
            regs: arg_reg_ids(arch, platform),
            base: sp + stack_arg_base(arch, platform),
            next: 0,
            float_next: 0,
        }
    }

    /// Start reading after the first `n` fixed arguments (the format string).
    pub fn start_at(mut self, n: usize) -> Self {
        self.next = n;
        self
    }

    pub fn next_u64(&mut self) -> u64 {
        let index = self.next;
        self.next += 1;
        if index < self.regs.len() {
            self.uc.reg_read(self.regs[index]).unwrap_or(0)
        } else {
            let addr = self.base + (index - self.regs.len()) as u64 * self.arch.ptr_size();
            read_ptr(self.uc, self.arch, addr).unwrap_or(0)
        }
    }

    pub fn next_i64(&mut self) -> i64 {
        self.next_u64() as i64
    }

    pub fn next_string(&mut self, max: usize) -> String {
        let ptr = self.next_u64();
        read_cstr_string(self.uc, ptr, max)
    }

    /// Floating point varargs live in their own register file on x86-64 and
    /// AArch64. This is approximate for stack overflow, but exact for the
    /// common case of a handful of doubles.
    pub fn next_f64(&mut self) -> f64 {
        let index = self.float_next;
        self.float_next += 1;
        let reg = match self.arch {
            Arch::X86_64 => Some(RegisterX86::XMM0 as i32 + index as i32),
            Arch::Arm64 => Some(RegisterARM64::D0 as i32 + index as i32),
            _ => None,
        };
        if let Some(id) = reg {
            if index < 8 {
                if let Ok(buf) = self.uc.reg_read_long(id) {
                    if buf.len() >= 8 {
                        return f64::from_le_bytes(buf[..8].try_into().unwrap());
                    }
                }
            }
        }
        0.0
    }
}

/// Read the syscall argument registers as an array of six values.
pub fn syscall_args(uc: &Uc<'_>, arch: Arch) -> [u64; 6] {
    let ids: Vec<i32> = match arch {
        Arch::X86_64 => vec![
            RegisterX86::RDI as i32,
            RegisterX86::RSI as i32,
            RegisterX86::RDX as i32,
            RegisterX86::R10 as i32,
            RegisterX86::R8 as i32,
            RegisterX86::R9 as i32,
        ],
        Arch::X86 => vec![
            RegisterX86::EBX as i32,
            RegisterX86::ECX as i32,
            RegisterX86::EDX as i32,
            RegisterX86::ESI as i32,
            RegisterX86::EDI as i32,
            RegisterX86::EBP as i32,
        ],
        Arch::Arm => vec![
            RegisterARM::R0 as i32,
            RegisterARM::R1 as i32,
            RegisterARM::R2 as i32,
            RegisterARM::R3 as i32,
            RegisterARM::R4 as i32,
            RegisterARM::R5 as i32,
        ],
        Arch::Arm64 => vec![
            RegisterARM64::X0 as i32,
            RegisterARM64::X1 as i32,
            RegisterARM64::X2 as i32,
            RegisterARM64::X3 as i32,
            RegisterARM64::X4 as i32,
            RegisterARM64::X5 as i32,
        ],
    };
    let mut out = [0u64; 6];
    for (i, id) in ids.iter().enumerate() {
        out[i] = uc.reg_read(*id).unwrap_or(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forced_return_applies_to_functions_that_compute_a_value() {
        assert!(Override {
            name: "strlen".into(),
            ret: Some(1)
        }
        .ret_applies());
        assert!(Override {
            name: "GetTickCount".into(),
            ret: Some(1)
        }
        .ret_applies());
    }

    #[test]
    fn a_forced_return_is_ignored_where_zero_would_be_a_null_pointer() {
        for name in ["malloc", "calloc", "fopen", "strdup", "open", "openat"] {
            assert!(
                !Override {
                    name: name.into(),
                    ret: Some(0)
                }
                .ret_applies(),
                "{name} must keep the pointer the stub handed back"
            );
        }
    }

    #[test]
    fn register_names_follow_the_disassembly() {
        assert_eq!(reg_id(Arch::X86_64, "rax"), Some(RegisterX86::RAX as i32));
        assert_eq!(reg_id(Arch::X86_64, "%RIP"), Some(RegisterX86::RIP as i32));
        assert_eq!(reg_id(Arch::X86_64, "r8"), Some(RegisterX86::R8 as i32));
        assert_eq!(reg_id(Arch::X86_64, "r15"), Some(RegisterX86::R15 as i32));
        assert_eq!(reg_id(Arch::X86, "eax"), Some(RegisterX86::EAX as i32));
        assert_eq!(reg_id(Arch::Arm64, "x0"), Some(RegisterARM64::X0 as i32));
        assert_eq!(
            reg_id(Arch::Arm64, "x3"),
            Some(RegisterARM64::X0 as i32 + 3)
        );
        assert_eq!(reg_id(Arch::Arm64, "lr"), Some(RegisterARM64::X30 as i32));
        assert_eq!(reg_id(Arch::Arm, "r7"), Some(RegisterARM::R0 as i32 + 7));
    }

    #[test]
    fn registers_that_do_not_exist_are_not_invented() {
        assert_eq!(reg_id(Arch::X86_64, "r16"), None);
        assert_eq!(reg_id(Arch::X86_64, "eax"), None);
        assert_eq!(reg_id(Arch::Arm64, "x29plus"), None);
        assert_eq!(reg_id(Arch::Arm, "r13"), Some(RegisterARM::SP as i32));
        assert_eq!(reg_id(Arch::X86_64, ""), None);
    }
}
