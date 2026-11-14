//! Frida hook scripts for a function in a native binary.
//!
//! Static analysis says what a function *can* do; a hook says what it is
//! actually called with, and what it returns — the one fact a decompiler
//! cannot supply. This module writes the script (Frida 16 and 17 spell the
//! export lookup differently, so both are tried) and, on request, runs it
//! against a local process and returns what it printed.
//!
//! Nothing here links Frida: `frida` is a Python tool, spawned as a child.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use goblin::Object;

use crate::decompilers::parse_address;
use crate::external::{capture, which};
use crate::resolve::{cache_root, resolve};
use crate::util::read_spec;

/// How many arguments to log by default. More than four is rarely what a
/// function reads, and each one costs a log line on every call.
const DEFAULT_ARGS: usize = 4;
const SPAWN_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Request {
    /// Optional: tells the generator the architecture and the exports.
    pub path: Option<String>,
    pub symbol: Option<String>,
    pub address: Option<String>,
    /// Module name as Frida sees it; defaults to the file name.
    pub module: Option<String>,
    /// How many arguments to log.
    pub args: usize,
    /// Extra JS for onEnter.
    pub on_enter: Option<String>,
    /// Extra JS for onLeave.
    pub on_leave: Option<String>,
    /// gen | spawn
    pub mode: String,
    /// spawn: the command to start under Frida, e.g. `/usr/bin/app --flag`.
    pub spawn: Option<String>,
}

impl Default for Request {
    fn default() -> Self {
        Request {
            path: None,
            symbol: None,
            address: None,
            module: None,
            args: DEFAULT_ARGS,
            on_enter: None,
            on_leave: None,
            mode: "gen".to_string(),
            spawn: None,
        }
    }
}

pub fn run(req: &Request) -> Result<String> {
    let symbol = req
        .symbol
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let address = req
        .address
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty());
    if symbol.is_none() && address.is_none() {
        bail!("pass symbol or address: a hook needs a function to attach to");
    }
    if symbol.is_some() && address.is_some() {
        bail!("pass either symbol or address, not both");
    }

    let mode = req.mode.trim().to_ascii_lowercase();
    let mode = if mode.is_empty() {
        "gen".to_string()
    } else {
        mode
    };
    if mode != "gen" && mode != "spawn" {
        bail!("unknown mode {mode:?}: use gen or spawn");
    }

    let binary = match req.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(spec) => Some(inspect(spec, symbol)?),
        None => None,
    };

    let script = generate(req, symbol, address, binary.as_ref());
    if mode == "gen" {
        return Ok(script);
    }

    let spawn = req
        .spawn
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("mode=spawn needs a command to start, e.g. spawn=\"/bin/ls -l\""))?;

    let path = script_path(symbol, address);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, &script)?;

    let output = spawn_under_frida(&path, spawn)?;
    Ok(format!(
        "frida: {spawn}\n{}\n\nscript: {}\n",
        output.trim_end(),
        path.display()
    ))
}

/// What the binary itself says: architecture, the module name Frida will use,
/// the exports available to hook, and the base needed to turn a file address
/// into a runtime one.
struct Binary {
    arch: String,
    bits: u32,
    module: String,
    /// Preferred load address, subtracted from a file address to get an offset
    /// into the mapped image.
    image_base: u64,
    exports: Vec<(String, u64)>,
}

fn inspect(spec: &str, symbol: Option<&str>) -> Result<Binary> {
    let path = resolve(spec)?;
    let info = crate::info::analyze(spec)?;
    if !matches!(info.format.as_str(), "ELF" | "PE32" | "PE32+" | "Mach-O") {
        bail!(
            "{} is {} — Frida hooks native code, not this",
            path.display(),
            info.format
        );
    }
    let (_, data) = read_spec(spec)?;
    let module = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "module".to_string());
    let exports: Vec<(String, u64)> = crate::symbols::exports(spec, 20_000, None)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|sym| sym.addr.map(|addr| (sym.name, addr)))
        .collect();

    if let Some(symbol) = symbol {
        if !exports.iter().any(|(name, _)| name == symbol) {
            let lower = symbol.to_ascii_lowercase();
            let near: Vec<&str> = exports
                .iter()
                .map(|(name, _)| name.as_str())
                .filter(|name| name.to_ascii_lowercase().contains(&lower))
                .take(8)
                .collect();
            if near.is_empty() {
                bail!(
                    "{symbol:?} is not exported by {}; a hook needs an exported name or an \
                     address (see `exports`), and a stripped binary has to be hooked by address",
                    path.display()
                );
            }
            bail!(
                "{symbol:?} is not exported by {}. Similar names: {}",
                path.display(),
                near.join(", ")
            );
        }
    }

    Ok(Binary {
        arch: info.arch,
        bits: info.bits,
        module,
        image_base: image_base(&data).unwrap_or(0),
        exports,
    })
}

/// The address the file is linked at. A shared object is linked at zero, an
/// executable at its image base, and Frida reports both through
/// `Module.base` — so a file address has to be reduced by this to be an
/// offset into the mapped module.
fn image_base(data: &[u8]) -> Option<u64> {
    match Object::parse(data).ok()? {
        Object::Elf(elf) => elf
            .program_headers
            .iter()
            .filter(|program| program.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|program| program.p_vaddr)
            .min(),
        Object::PE(pe) => Some(pe.image_base as u64),
        Object::Mach(mach) => {
            let segments: Vec<u64> = match mach {
                goblin::mach::Mach::Binary(binary) => binary
                    .segments
                    .iter()
                    .map(|segment| segment.vmaddr)
                    .collect(),
                goblin::mach::Mach::Fat(fat) => {
                    // A universal binary holds several slices, each with its own
                    // base; the smallest is the one an address is measured from.
                    let mut out = Vec::new();
                    for index in 0..fat.narches {
                        if let Ok(goblin::mach::SingleArch::MachO(binary)) = fat.get(index) {
                            out.extend(binary.segments.iter().map(|s| s.vmaddr));
                        }
                    }
                    out
                }
            };
            segments.into_iter().min()
        }
        _ => None,
    }
}

fn script_path(symbol: Option<&str>, address: Option<&str>) -> std::path::PathBuf {
    let name = symbol.or(address).unwrap_or("hook");
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    cache_root().join(format!("hook-{safe}.js"))
}

fn generate(
    req: &Request,
    symbol: Option<&str>,
    address: Option<&str>,
    binary: Option<&Binary>,
) -> String {
    let module = req
        .module
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .or_else(|| binary.map(|b| b.module.clone()))
        .unwrap_or_else(|| "your-module".to_string());
    let label = symbol
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{}", address.unwrap_or("0")));
    let arch = binary
        .map(|b| format!("{}, {}-bit", b.arch, b.bits))
        .unwrap_or_else(|| "unknown".to_string());
    let nargs = req.args.min(8);

    let mut out = String::new();
    out.push_str(&format!(
        "// Generated by rekit hook.\n\
         //\n\
         // target : {label} in {module}\n\
         // arch   : {arch}\n\
         // frida  : 16 and 17 — Module.findExportByName was replaced by\n\
         //          Module.getGlobalExportByName, so both are tried below.\n\
         //\n\
         // spawn : frida -f <process> -l hook.js\n\
         // attach: frida -p <pid> -l hook.js\n\
         //\n\
         // If the pipx `frida` shim is broken (wrong shebang, missing colorama),\n\
         // run the venv's own interpreter:\n\
         //   ~/.local/share/pipx/venvs/frida-tools/bin/python \\\n\
         //     -c \"import sys; from frida_tools.repl import main; \\\n\
         //         sys.argv=['frida','-l','hook.js','-f','<process>']; main()\"\n\
         \n\
         const MODULE = '{module}';\n\
         \n\
         function findModule(name) {{\n\
         \x20 try {{ return Process.getModuleByName(name); }} catch (e) {{}}\n\
         \x20 const found = Process.enumerateModules().filter(function (m) {{\n\
         \x20   return m.name.indexOf(name) !== -1;\n\
         \x20 }});\n\
         \x20 return found.length > 0 ? found[0] : null;\n\
         }}\n\
         \n\
         function findExport(name) {{\n\
         \x20 // Frida 17\n\
         \x20 if (typeof Module.getGlobalExportByName === 'function') {{\n\
         \x20   try {{ return Module.getGlobalExportByName(name); }} catch (e) {{}}\n\
         \x20 }}\n\
         \x20 // Frida 16\n\
         \x20 if (typeof Module.findGlobalExportByName === 'function') {{\n\
         \x20   const at = Module.findGlobalExportByName(name);\n\
         \x20   if (at !== null) return at;\n\
         \x20 }}\n\
         \x20 if (typeof Module.findExportByName === 'function') {{\n\
         \x20   const at = Module.findExportByName(null, name);\n\
         \x20   if (at !== null) return at;\n\
         \x20 }}\n\
         \x20 const mod = findModule(MODULE);\n\
         \x20 if (mod !== null && typeof mod.findExportByName === 'function') {{\n\
         \x20   return mod.findExportByName(name);\n\
         \x20 }}\n\
         \x20 return null;\n\
         }}\n\
         \n"
    ));

    match (symbol, address) {
        (Some(symbol), _) => {
            if let Some(binary) = binary {
                if let Some((_, addr)) = binary.exports.iter().find(|(name, _)| name == symbol) {
                    out.push_str(&format!(
                        "// {symbol} is exported at file address 0x{addr:x}\n"
                    ));
                }
            }
            out.push_str(&format!("const target = findExport('{symbol}');\n"));
        }
        (None, Some(address)) => {
            let file_address = match parse_address(address) {
                Ok(addr) => addr,
                Err(err) => {
                    out.push_str(&format!("// address {address:?} was not readable: {err}\n"));
                    0
                }
            };
            let base = binary.map(|b| b.image_base).unwrap_or(0);
            let offset = file_address.wrapping_sub(base);
            out.push_str(&format!(
                "// File address 0x{file_address:x} minus image base 0x{base:x} is the offset\n\
                 // into the mapped module: 0x{offset:x}.\n\
                 const mod = findModule(MODULE);\n\
                 const target = mod === null ? null : mod.base.add(0x{offset:x});\n"
            ));
        }
        (None, None) => unreachable!("checked by run()"),
    }

    out.push_str(&format!(
        "\nif (target === null || target === undefined) {{\n\
         \x20 console.log('[!] could not resolve {label} in ' + MODULE + ': check the');\n\
         \x20 console.log('    module name (a library may be loaded later), or, for an');\n\
         \x20 console.log('    address, the offset into the module.');\n\
         }} else {{\n\
         \x20 console.log('[+] {label} @ ' + target);\n\
         \x20 Interceptor.attach(target, {{\n\
         \x20   onEnter(args) {{\n"
    ));
    if nargs == 0 {
        out.push_str(&format!("\x20     console.log('[->] {label}');\n"));
    } else {
        out.push_str("\x20     this.a = [];\n");
        for index in 0..nargs {
            out.push_str(&format!(
                "\x20     this.a.push('a{index}=' + args[{index}]);\n"
            ));
        }
        out.push_str(&format!(
            "\x20     console.log('[->] {label}(' + this.a.join(', ') + ')');\n"
        ));
    }
    push_user_code(&mut out, req.on_enter.as_deref());
    out.push_str(&format!(
        "\x20   }},\n\
         \x20   onLeave(retval) {{\n\
         \x20     console.log('[<-] {label} = ' + retval);\n"
    ));
    push_user_code(&mut out, req.on_leave.as_deref());
    out.push_str(
        "\x20   },\n\
         \x20 });\n\
         }\n",
    );
    out
}

/// User JS goes in verbatim, indented to match the block it lands in. A
/// trailing newline is added only when missing, and blank lines are left blank
/// rather than carrying indentation.
fn push_user_code(out: &mut String, code: Option<&str>) {
    let Some(code) = code.map(str::trim).filter(|code| !code.is_empty()) else {
        return;
    };
    out.push_str("\x20     // custom\n");
    for line in code.lines() {
        if line.trim().is_empty() {
            out.push('\n');
        } else {
            out.push_str(&format!("\x20     {}\n", line.trim_end()));
        }
    }
}

/// Where a working Frida lives.
///
/// The PATH shim from pipx is commonly broken, and a bare `python3` usually
/// lacks the module, so each candidate is probed by actually importing it.
fn frida_python() -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(path) = std::env::var_os("FRIDA_PY") {
        candidates.push(path.to_string_lossy().to_string());
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        candidates.push(
            home.join(".local/share/pipx/venvs/frida-tools/bin/python")
                .to_string_lossy()
                .to_string(),
        );
        candidates.push(
            home.join(".local/share/uv/tools/frida-tools/bin/python")
                .to_string_lossy()
                .to_string(),
        );
    }
    for name in ["frida", "python3"] {
        if let Some(path) = which(name) {
            candidates.push(path.to_string_lossy().to_string());
        }
    }

    for candidate in candidates {
        if !Path::new(&candidate).is_file() {
            continue;
        }
        // The driver needs only `frida`; frida_tools is for the REPL, which is
        // not used here.
        let args = vec!["-c".to_string(), "import frida".to_string()];
        if let Ok(out) = capture(&candidate, &args, Duration::from_secs(20), &[], None) {
            if out.success && !out.timed_out {
                return Some(candidate);
            }
        }
    }
    None
}

fn spawn_under_frida(script: &Path, command: &str) -> Result<String> {
    let python = frida_python().ok_or_else(|| {
        anyhow!(
            "no Frida with a working frida library was found. Install it \
             (`pacman -S frida-tools` or `pipx install frida-tools`), point FRIDA_PY at \
             its interpreter, or use mode=gen and run the script yourself."
        )
    })?;

    let tokens = split_command(command);
    let (program, extra) = tokens
        .split_first()
        .ok_or_else(|| anyhow!("spawn is empty"))?;
    if !Path::new(program).is_file() {
        bail!("spawn: {program} is not a file; pass the full path, e.g. /usr/bin/app --flag");
    }

    let mut args: Vec<String> = vec![
        "-c".to_string(),
        DRIVER.to_string(),
        script.display().to_string(),
        program.clone(),
    ];
    args.extend(extra.iter().cloned());

    let out = capture(&python, &args, SPAWN_TIMEOUT, &[], None)?;
    let combined = format!("{}\n{}", out.stdout, out.stderr);

    if out.timed_out {
        bail!(
            "the target did not exit within {}s — most likely it waits for input or runs \
             forever, and it may still be running. Use mode=gen, run the script yourself \
             and stop it when you have seen enough.\n\n{}",
            SPAWN_TIMEOUT.as_secs(),
            cap(&combined, 40)
        );
    }
    if combined.contains("No module named") || combined.contains("ModuleNotFoundError") {
        bail!(
            "the Frida environment is missing modules:\n{}\nInstall into the frida-tools \
             venv, not into the system python.",
            cap(&combined, 10)
        );
    }
    if !out.success && combined.trim().is_empty() {
        bail!("frida exited with a failure and printed nothing");
    }
    Ok(combined)
}

/// The Python side of `mode=spawn`.
///
/// This is the Frida API rather than the `frida` REPL: the REPL exits as soon
/// as its stdin reaches EOF, which happens immediately when it is spawned from
/// another program, and every hook message still in flight is lost. Owning the
/// session here means the hook output is printed as it arrives, and the
/// process is watched until it really ends.
const DRIVER: &str = r#"
import sys, threading, time
import frida

script_path = sys.argv[1]
argv = sys.argv[2:]

device = frida.get_local_device()
try:
    pid = device.spawn(argv)
except Exception as err:
    sys.stderr.write('frida could not start %s: %s\n' % (argv[0], err))
    sys.exit(2)

session = device.attach(pid)
done = threading.Event()

def on_message(message, data):
    kind = message.get('type')
    if kind == 'log':
        print(message.get('payload', ''), flush=True)
    elif kind == 'error':
        detail = message.get('stack') or message.get('description') or message
        print('[script error] %s' % (detail,), flush=True)
    elif kind == 'send':
        print('[send] %s' % (message.get('payload'),), flush=True)

def on_detached(reason, *rest):
    print('[frida] process ended: %s' % (reason,), flush=True)
    done.set()

with open(script_path) as handle:
    source = handle.read()

script = session.create_script(source, runtime='v8')
script.on('message', on_message)
session.on('detached', on_detached)
try:
    script.load()
except Exception as err:
    sys.stderr.write('frida could not load the script: %s\n' % (err,))
    device.kill(pid)
    sys.exit(2)

device.resume(pid)
while not done.wait(0.2):
    pass

# A message already on the wire can still land after the process is gone.
time.sleep(0.3)
"#;

/// Split a command line into tokens, honouring single and double quotes: a
/// process started with an argument that contains spaces is common enough that
/// splitting on whitespace alone would start the wrong thing.
fn split_command(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;

    for ch in text.chars() {
        match quote {
            Some(q) if ch == q => {
                quote = None;
                started = true;
            }
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                started = true;
            }
            None if ch.is_whitespace() => {
                if started || !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            None => {
                current.push(ch);
                started = true;
            }
        }
    }
    if started || !current.is_empty() {
        out.push(current);
    }
    out
}

fn cap(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    if all.len() <= lines {
        return text.to_string();
    }
    format!(
        "{}\n... {} more lines",
        all[..lines].join("\n"),
        all.len() - lines
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            symbol: Some("hooked".into()),
            ..Request::default()
        }
    }

    #[test]
    fn the_script_works_on_both_frida_spellings() {
        let text = generate(&request(), Some("hooked"), None, None);
        // Frida 17 removed findExportByName; a script that only knows the old
        // name silently fails to attach on the new one.
        assert!(text.contains("Module.getGlobalExportByName"));
        assert!(text.contains("Module.findGlobalExportByName"));
        assert!(text.contains("Module.findExportByName(null, name)"));
        assert!(text.contains("mod.findExportByName(name)"));
    }

    #[test]
    fn the_module_falls_back_to_a_substring_match() {
        let text = generate(&request(), Some("hooked"), None, None);
        assert!(text.contains("const MODULE = 'your-module'"));
        assert!(text.contains("m.name.indexOf(name) !== -1"));
    }

    #[test]
    fn arguments_are_logged_up_to_the_requested_count() {
        let mut req = request();
        req.args = 3;
        let text = generate(&req, Some("hooked"), None, None);
        assert!(text.contains("a0"));
        assert!(text.contains("a2"));
        assert!(!text.contains("a3"));

        req.args = 0;
        let text = generate(&req, Some("hooked"), None, None);
        assert!(text.contains("console.log('[->] hooked');"));
        assert!(!text.contains("this.a"));
    }

    #[test]
    fn custom_code_is_indented_into_the_block() {
        let mut req = request();
        req.on_enter = Some("if (args[0].toInt32() === 7) {\n  console.log('seven');\n}".into());
        req.on_leave = Some("console.log('len=' + ptr(this.a[0]).readUtf8String());".into());
        let text = generate(&req, Some("hooked"), None, None);
        assert!(text.contains("      // custom\n      if (args[0].toInt32() === 7) {"));
        assert!(text.contains("\n        console.log('seven');"));
        assert!(text.contains("      console.log('len='"));
    }

    #[test]
    fn an_address_becomes_an_offset_into_the_mapped_module() {
        let binary = Binary {
            arch: "x86_64".into(),
            bits: 64,
            module: "libx.so".into(),
            image_base: 0x400000,
            exports: Vec::new(),
        };
        let text = generate(&request(), None, Some("0x4011bd"), Some(&binary));
        // 0x4011bd - 0x400000: the file address is not the runtime address.
        assert!(text.contains("mod.base.add(0x11bd)"));
        assert!(text.contains("minus image base 0x400000"));
        // The helper is always defined; what matters is that the target is not
        // looked up by name when an address was given.
        assert!(!text.contains("const target = findExport"));
    }

    #[test]
    fn without_a_binary_the_file_address_is_the_offset() {
        // No path means no image base to subtract, which is right for a shared
        // object: it is linked at zero, so the file address is the offset.
        let text = generate(&request(), None, Some("0x11bd"), None);
        assert!(text.contains("mod.base.add(0x11bd)"));
        assert!(text.contains("minus image base 0x0"));
        assert!(text.contains("const mod = findModule(MODULE)"));
    }

    #[test]
    fn a_target_command_is_split_on_quotes() {
        assert_eq!(split_command("/bin/ls -l"), vec!["/bin/ls", "-l"]);
        assert_eq!(
            split_command("/bin/echo 'a b' \"c d\""),
            vec!["/bin/echo", "a b", "c d"]
        );
        assert_eq!(split_command("  /bin/true  "), vec!["/bin/true"]);
        assert!(split_command("   ").is_empty());
    }

    #[test]
    fn the_script_name_is_safe_to_write() {
        let path = script_path(Some("std::foo<bar>"), None);
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name, "hook-std__foo_bar_.js");
        assert!(path.starts_with(cache_root()));
    }
}
