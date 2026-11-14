//! A JNIEnv, so native code can call back into Java.
//!
//! JNI is a table of function pointers: `env->functions->FindClass(env, ...)`
//! reads a pointer out of a table and jumps to it. That is what makes it
//! tractable here — the same trick the real VM uses also works for a fake one,
//! so native code with a `JNIEnv*` first argument can be run without a JVM.
//!
//! What is answered honestly, rather than with a convenient zero:
//!
//! - `NewStringUTF` remembers the text, and `GetStringUTFChars` on that handle
//!   reads it back. A licence check that compares a string therefore passes or
//!   fails on the string it actually produced, not on an empty answer.
//! - `ExceptionOccurred` and `ExceptionCheck` say there is no exception, which
//!   is the truth: nothing was thrown inside the emulator.
//! - `RegisterNatives` returns `JNI_OK`, and `GetVersion` returns 1.6, because
//!   a version check is otherwise a branch on an invented number.
//!
//! What cannot be answered is anything that needs the Java side: every
//! `Call*Method` returns 0. For an `int` that is a plausible value; for an
//! object it is NULL, and code that dereferences it will fault — honestly,
//! rather than with a pointer into nothing.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::Result;
use unicorn_engine::unicorn_const::Prot;

use crate::emu::{read_cstr_string, write_ptr, State, Uc};
use crate::imports::arg_at;

/// The table, `env`, and the objects handed out live away from the image, the
/// stubs and the heap, so nothing the guest owns can collide with them.
const TABLE_BASE: u64 = 0x3100_0000;
const ENV_BASE: u64 = 0x3110_0000;
const VM_BASE: u64 = 0x3130_0000;
const OBJ_BASE: u64 = 0x3120_0000;
const OBJ_SPAN: u64 = 0x1_0000;

/// Slot index → name, in the order the real `JNINativeInterface` declares them.
/// The gaps are the `reserved` slots and the variants added by later JDKs.
pub const NAMES: &[(u32, &str)] = &[
    (4, "GetVersion"),
    (6, "FindClass"),
    (10, "GetSuperclass"),
    (13, "Throw"),
    (14, "ThrowNew"),
    (15, "ExceptionOccurred"),
    (16, "ExceptionDescribe"),
    (17, "ExceptionClear"),
    (18, "FatalError"),
    (19, "PushLocalFrame"),
    (20, "PopLocalFrame"),
    (21, "NewGlobalRef"),
    (22, "DeleteGlobalRef"),
    (23, "DeleteLocalRef"),
    (24, "IsSameObject"),
    (25, "NewLocalRef"),
    (26, "EnsureLocalCapacity"),
    (27, "AllocObject"),
    (28, "NewObject"),
    (31, "GetObjectClass"),
    (32, "IsInstanceOf"),
    (33, "GetMethodID"),
    (34, "CallObjectMethod"),
    (37, "CallBooleanMethod"),
    (40, "CallByteMethod"),
    (43, "CallCharMethod"),
    (46, "CallShortMethod"),
    (49, "CallIntMethod"),
    (52, "CallLongMethod"),
    (55, "CallFloatMethod"),
    (58, "CallDoubleMethod"),
    (61, "CallVoidMethod"),
    (94, "GetFieldID"),
    (95, "GetObjectField"),
    (96, "GetBooleanField"),
    (97, "GetByteField"),
    (98, "GetCharField"),
    (99, "GetShortField"),
    (100, "GetIntField"),
    (101, "GetLongField"),
    (102, "GetFloatField"),
    (103, "GetDoubleField"),
    (104, "SetObjectField"),
    (105, "SetBooleanField"),
    (106, "SetByteField"),
    (107, "SetCharField"),
    (108, "SetShortField"),
    (109, "SetIntField"),
    (110, "SetLongField"),
    (111, "SetFloatField"),
    (112, "SetDoubleField"),
    (113, "GetStaticMethodID"),
    (114, "CallStaticObjectMethod"),
    (117, "CallStaticBooleanMethod"),
    (120, "CallStaticByteMethod"),
    (123, "CallStaticCharMethod"),
    (126, "CallStaticShortMethod"),
    (129, "CallStaticIntMethod"),
    (132, "CallStaticLongMethod"),
    (135, "CallStaticFloatMethod"),
    (138, "CallStaticDoubleMethod"),
    (141, "CallStaticVoidMethod"),
    (144, "GetStaticFieldID"),
    (145, "GetStaticObjectField"),
    (146, "GetStaticBooleanField"),
    (147, "GetStaticByteField"),
    (148, "GetStaticCharField"),
    (149, "GetStaticShortField"),
    (150, "GetStaticIntField"),
    (151, "GetStaticLongField"),
    (152, "GetStaticFloatField"),
    (153, "GetStaticDoubleField"),
    (154, "SetStaticObjectField"),
    (155, "SetStaticBooleanField"),
    (156, "SetStaticByteField"),
    (157, "SetStaticCharField"),
    (158, "SetStaticShortField"),
    (159, "SetStaticIntField"),
    (160, "SetStaticLongField"),
    (161, "SetStaticFloatField"),
    (162, "SetStaticDoubleField"),
    (163, "NewString"),
    (164, "GetStringLength"),
    (165, "GetStringChars"),
    (166, "ReleaseStringChars"),
    (167, "NewStringUTF"),
    (168, "GetStringUTFLength"),
    (169, "GetStringUTFChars"),
    (170, "ReleaseStringUTFChars"),
    (171, "GetArrayLength"),
    (172, "NewObjectArray"),
    (173, "GetObjectArrayElement"),
    (174, "SetObjectArrayElement"),
    (175, "NewBooleanArray"),
    (176, "NewByteArray"),
    (177, "NewCharArray"),
    (178, "NewShortArray"),
    (179, "NewIntArray"),
    (180, "NewLongArray"),
    (181, "NewFloatArray"),
    (182, "NewDoubleArray"),
    (183, "GetBooleanArrayElements"),
    (184, "GetByteArrayElements"),
    (185, "GetCharArrayElements"),
    (186, "GetShortArrayElements"),
    (187, "GetIntArrayElements"),
    (188, "GetLongArrayElements"),
    (189, "GetFloatArrayElements"),
    (190, "GetDoubleArrayElements"),
    (191, "ReleaseBooleanArrayElements"),
    (192, "ReleaseByteArrayElements"),
    (193, "ReleaseCharArrayElements"),
    (194, "ReleaseShortArrayElements"),
    (195, "ReleaseIntArrayElements"),
    (196, "ReleaseLongArrayElements"),
    (197, "ReleaseFloatArrayElements"),
    (198, "ReleaseDoubleArrayElements"),
    (199, "GetBooleanArrayRegion"),
    (200, "GetByteArrayRegion"),
    (201, "GetCharArrayRegion"),
    (202, "GetShortArrayRegion"),
    (203, "GetIntArrayRegion"),
    (204, "GetLongArrayRegion"),
    (205, "GetFloatArrayRegion"),
    (206, "GetDoubleArrayRegion"),
    (207, "SetBooleanArrayRegion"),
    (208, "SetByteArrayRegion"),
    (209, "SetCharArrayRegion"),
    (210, "SetShortArrayRegion"),
    (211, "SetIntArrayRegion"),
    (212, "SetLongArrayRegion"),
    (213, "SetFloatArrayRegion"),
    (214, "SetDoubleArrayRegion"),
    (215, "RegisterNatives"),
    (216, "UnregisterNatives"),
    (217, "MonitorEnter"),
    (218, "MonitorExit"),
    (219, "GetJavaVM"),
    (226, "DeleteWeakGlobalRef"),
    (228, "ExceptionCheck"),
    (229, "NewDirectByteBuffer"),
    (230, "GetDirectBufferAddress"),
    (231, "GetDirectBufferCapacity"),
    (232, "GetObjectRefType"),
];

pub(crate) fn install(
    uc: &mut Uc<'_>,
    st: &Rc<RefCell<State>>,
    stubs: &mut HashMap<String, u64>,
) -> Result<()> {
    for (base, size) in [
        (TABLE_BASE, 0x1000u64),
        (ENV_BASE, 0x1000),
        (OBJ_BASE, OBJ_SPAN),
    ] {
        uc.mem_map(base, size, Prot::ALL)
            .map_err(|e| anyhow::anyhow!("cannot map the JNI region at {base:#x}: {e}"))?;
    }

    let arch = st.borrow().arch;
    let mut addresses: Vec<(u32, u64)> = Vec::with_capacity(NAMES.len());
    for (slot, name) in NAMES {
        let stub = crate::emu::stub_for(uc, st, stubs, &format!("JNI:{name}"))?;
        addresses.push((*slot, stub));
    }
    for (slot, stub) in addresses {
        write_ptr(uc, arch, TABLE_BASE + slot as u64 * arch.ptr_size(), stub)?;
    }
    write_ptr(uc, arch, ENV_BASE, TABLE_BASE)?;

    let mut state = st.borrow_mut();
    state.jni_env = ENV_BASE;
    state.jni_table = TABLE_BASE;
    state.jni_vm = VM_BASE;
    Ok(())
}

/// Answer one call from the JNI table. The name has no `JNI:` prefix here.
pub fn call(uc: &mut Uc<'_>, st: &mut State, name: &str) -> u64 {
    if !st.jni_noted {
        st.jni_noted = true;
        st.notes.push(format!(
            "JNIEnv at {:#x}: JNI calls are answered (strings round-trip, no exception is pending)",
            st.jni_env
        ));
    }
    let arch = st.arch;
    let platform = st.platform;
    let a1 = arg_at(uc, arch, platform, 1);
    let a2 = arg_at(uc, arch, platform, 2);
    let a3 = arg_at(uc, arch, platform, 3);

    match name {
        "GetVersion" => 0x0001_0006,
        "ExceptionOccurred" | "ExceptionCheck" | "ExceptionClear" | "ExceptionDescribe" => 0,
        "Throw" | "ThrowNew" | "FatalError" => 0,
        "PushLocalFrame" | "PopLocalFrame" | "EnsureLocalCapacity" => 0,
        "NewGlobalRef" | "NewLocalRef" => a1,
        "DeleteGlobalRef" | "DeleteLocalRef" | "DeleteWeakGlobalRef" => 0,
        "IsSameObject" => u64::from(a1 == a2),
        "IsInstanceOf" => 1,
        "FindClass" | "GetObjectClass" | "GetSuperclass" | "AllocObject" | "NewObject" => {
            object(st, Kind::Class, a1)
        }
        "GetMethodID" | "GetStaticMethodID" | "GetFieldID" | "GetStaticFieldID" => {
            object(st, Kind::Method, a1 ^ a2 ^ a3)
        }
        "NewString" | "NewStringUTF" => {
            // The handle is what later calls receive, so the text has to be
            // remembered under it: that is what makes a string comparison in
            // the emulated code mean something.
            let text = read_cstr_string(uc, a1, 1 << 16);
            let handle = object(st, Kind::String, a1);
            st.jni_strings.insert(handle, text);
            handle
        }
        "GetStringUTFChars" | "GetStringChars" => {
            let text = match st.jni_strings.get(&a1) {
                Some(text) => text.clone(),
                None => read_cstr_string(uc, a1, 1 << 16),
            };
            let buffer = st.alloc(uc, text.len() + 1);
            if buffer == 0 {
                return 0;
            }
            let mut bytes = text.into_bytes();
            bytes.push(0);
            let _ = uc.mem_write(buffer, &bytes);
            buffer
        }
        "ReleaseStringUTFChars" | "ReleaseStringChars" => 0,
        "GetStringLength" | "GetStringUTFLength" => match st.jni_strings.get(&a1) {
            Some(text) => text.len() as u64,
            None => read_cstr_string(uc, a1, 1 << 16).len() as u64,
        },
        "GetArrayLength" => 0,
        "GetObjectArrayElement" | "SetObjectArrayElement" => 0,
        "RegisterNatives" | "UnregisterNatives" => 0,
        "MonitorEnter" | "MonitorExit" => 0,
        "GetJavaVM" => {
            let vm = st.jni_vm;
            if a1 != 0 {
                let _ = write_ptr(uc, arch, a1, vm);
            }
            0
        }
        "NewDirectByteBuffer" => object(st, Kind::Buffer, a1),
        "GetDirectBufferAddress" => a1,
        "GetDirectBufferCapacity" => 0,
        "GetObjectRefType" => 0,
        _ if name.starts_with("New") && name.contains("Array") => object(st, Kind::Array, a1),
        _ if name.contains("ArrayElements") => {
            // A zeroed buffer the code may read and write. Its real length is
            // only knowable from the array object, which is a fake, so this is
            // a page rather than a promise: a caller that walks past it faults.
            st.alloc(uc, 0x1000)
        }
        _ if name.contains("ArrayRegion") => 0,
        _ if name.starts_with("Call") => 0,
        _ if name.contains("Field") => 0,
        // A function this table does not name cannot be answered better than
        // with zero; it is still counted, so the report says it happened.
        _ => 0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Class,
    Method,
    String,
    Array,
    Buffer,
}

/// A stable pseudo-reference: the same seed gives the same address, so
/// `obj == obj` and `IsSameObject` behave the way the code expects.
fn object(st: &mut State, kind: Kind, seed: u64) -> u64 {
    let key = (kind, seed);
    if let Some(&addr) = st.jni_objects.get(&key) {
        return addr;
    }
    let index = st.jni_objects.len() as u64 + 1;
    let addr = OBJ_BASE + index * 0x10;
    st.jni_objects.insert(key, addr);
    addr
}

/// Whether a first argument of zero should become the JNIEnv.
///
/// Substituting unconditionally would be wrong in the ordinary case: a
/// function called with a real zero argument would silently receive a pointer,
/// and `t_abs(0)` would return something enormous. So it happens only when the
/// name says the function is a JNI entry point, or when the caller asked for it
/// with the `env` argument.
pub fn wants_env(symbol: Option<&str>) -> bool {
    symbol.is_some_and(|name| name.starts_with("Java_") || name == "JNI_OnLoad")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_matches_the_jni_layout() {
        // These four are the calls the fixture makes; a slot that drifted would
        // still run, and would answer the wrong function.
        let slot = |name: &str| {
            NAMES
                .iter()
                .find(|(_, candidate)| *candidate == name)
                .map(|(slot, _)| *slot)
                .unwrap()
        };
        assert_eq!(slot("GetVersion"), 4);
        assert_eq!(slot("FindClass"), 6);
        assert_eq!(slot("NewStringUTF"), 167);
        assert_eq!(slot("GetStringUTFChars"), 169);
        assert_eq!(slot("GetJavaVM"), 219);
        assert_eq!(slot("ExceptionCheck"), 228);
    }

    #[test]
    fn slots_are_unique_and_ordered() {
        for pair in NAMES.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} after {}", pair[1].1, pair[0].1);
        }
    }

    #[test]
    fn the_environment_is_offered_only_where_it_makes_sense() {
        assert!(wants_env(Some("Java_com_example_Foo_probe")));
        assert!(wants_env(Some("JNI_OnLoad")));
        assert!(!wants_env(Some("jni_probe")));
        assert!(!wants_env(Some("t_abs")));
        assert!(!wants_env(None));
    }
}
