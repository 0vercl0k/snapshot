// Axel '0vercl0k' Souchet - January 15 2024
// Special cheers to @erynian for the inspiration 🙏
mod as_pcstr;
mod bits;
mod debug_client;
mod state;

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::{env, mem};

use anyhow::{bail, Result};
use chrono::Local;
use debug_client::DebugClient;
use serde_json::Value;
use state::{Float80, GlobalSeg, State, Zmm};
use windows::core::{IUnknown, HRESULT, PCSTR};
use windows::Win32::Foundation::{E_ABORT, S_OK};
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_CLASS_KERNEL, DEBUG_KERNEL_CONNECTION, DEBUG_KERNEL_EXDI_DRIVER, DEBUG_KERNEL_LOCAL,
};
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;

mod msr {
    pub const TSC: u32 = 0x0000_0010;
    pub const APIC_BASE: u32 = 0x0000_001b;
    pub const SYSENTER_CS: u32 = 0x0000_0174;
    pub const SYSENTER_ESP: u32 = 0x0000_0175;
    pub const SYSENTER_EIP: u32 = 0x0000_0176;
    pub const PAT: u32 = 0x0000_0277;
    pub const EFER: u32 = 0xc000_0080;
    pub const STAR: u32 = 0xc000_0081;
    pub const LSTAR: u32 = 0xc000_0082;
    pub const CSTAR: u32 = 0xc000_0083;
    pub const SFMASK: u32 = 0xc000_0084;
    pub const FS_BASE: u32 = 0xc000_0100;
    pub const GS_BASE: u32 = 0xc000_0101;
    pub const KERNEL_GS_BASE: u32 = 0xc000_0102;
    pub const TSC_AUX: u32 = 0xc000_0103;
}

enum SnapshotKind {
    ActiveKernel,
    Full,
}

/// Check if an address lives in user-mode.
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
fn is_usermode_addr(addr: u64) -> bool {
    addr <= 0x7FFF_FFFFFFFF
}

/// This function converts WinDbg's fptw register encoded value into what the
/// CPU expects fptw to be.
///
/// # Longer explanation
/// After a bit of reverse-engineering and dynamic analysis it would appear
/// that WinDbg's @fptw value is actually encoded the way `fxsave` saves it
/// as. You can read about `fxsave` here: https://www.felixcloutier.com/x86/fxsave.
///
/// In theory, @fptw is 16-bit integer and 2-bit patterns describe the
/// state of each of the 8 available FPU stack slot. This explains why the
/// register is 16-bit long as 2-bit per slot and there are 8 of them.
///
/// If you write assembly code to push values onto the FPU stack and dump the
/// value of @fptw, you'll see that it doesn't have the value you would
/// expect. Here is MASM VS x64 assembly to dump those values for the
/// curious readers:
///
/// ```
/// _TEXT SEGMENT
/// PUBLIC _fld
/// PUBLIC _fstenv
///
/// _fld PROC
/// fld qword ptr [rcx]
/// ret
/// _fld ENDP
///
/// _fstenv PROC
/// fstenv qword ptr [rcx]
/// ret
/// _fstenv ENDP
/// _TEXT ENDS
/// END
/// ```
///
/// And the C code to reads the value:
///
/// ```
/// #include <cstdio>
/// #include <cstdint>
/// #include <cstring>
///
/// extern "C" void _fld(const uint64_t*);
/// extern "C" void _fstenv(void*);
///
/// #pragma pack(1)
/// struct Fnstenv_t {
///     uint16_t fpcw;
///     uint16_t reserved0;
///     uint16_t fpsw;
///     uint16_t reserved1;
///     uint16_t fptw;
///     uint16_t reserved2;
///     uint32_t fpip;
///     uint16_t fpop_selector;
///     uint16_t fpop;
///     uint32_t fpdp;
///     uint16_t fpds;
///     uint16_t reserved3;
/// };
///
/// static_assert(sizeof(Fnstenv_t) == 28, "");
///
/// int main() {
///
///     Fnstenv_t f = {};
///     for (uint64_t Idx = 0; Idx < 8; Idx++) {
///         _fstenv(&f);
///         printf("real fptw: %x\n", f.fptw);
///         __debugbreak();
///         const uint64_t v = 1337 + Idx;
///         _fld(&v);
///
///     }
///     return 0;
/// }
/// ```
///
/// Below is a table I compiled that shows you the real @fptw register value
/// and what WinDbg gives you.
/// ```
/// +----------------+----------------+--------------------------------+
/// | State of stack | WinDbg's @fptw | Real fptw dumped with `fstenv` |
/// +----------------+----------------+--------------------------------+
/// | empty stack    |   0b00000000   +      0b11111111_11111111       |
/// +----------------+----------------+--------------------------------+
/// |    1 push      |   0b10000000   +      0b00111111_11111111       |
/// +----------------+----------------+--------------------------------+
/// |    2 push      |   0b11000000   +      0b00001111_11111111       |
/// +----------------+----------------+--------------------------------+
/// |    3 push      |   0b11100000   +      0b00000011_11111111       |
/// +----------------+----------------+--------------------------------+
/// |    4 push      |   0b11110000   +      0b00000000_11111111       |
/// +----------------+----------------+--------------------------------+
/// |    5 push      |   0b11111000   +      0b00000000_00111111       |
/// +----------------+----------------+--------------------------------+
/// |    6 push      |   0b11111100   +      0b00000000_00001111       |
/// +----------------+----------------+--------------------------------+
/// |    7 push      |   0b11111110   +      0b00000000_00000011       |
/// +----------------+----------------+--------------------------------+
/// |    9 push      |   0b11111111   +      0b00000000_00000000       |
/// +----------------+----------------+--------------------------------+
/// ```
fn fptw(windbg_fptw: u64) -> u64 {
    let mut out = 0;
    for bit_idx in 0..8 {
        let bits = (windbg_fptw >> bit_idx) & 0b1;
        out |= if bits == 1 { 0b00 } else { 0b11 } << (bit_idx * 2);
    }

    out
}

/// Generate a directory name where we'll store the CPU state / memory dump.
fn gen_state_folder_name(dbg: &DebugClient) -> Result<String> {
    let addr = dbg.get_address_by_name("nt!NtBuildLabEx")?;
    let build_name = dbg.read_cstring(addr)?;
    let now = Local::now();

    Ok(format!(
        "state.{build_name}.{}",
        now.format("%Y%m%d_%H%M")
    ))
}

/// Dump the register state.
fn state(dbg: &DebugClient) -> Result<State> {
    let mut regs = dbg.regs64_dict(&[
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rip", "rsp", "rbp", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15", "fpcw", "fpsw", "cr0", "cr2", "cr3", "cr4", "cr8", "xcr0",
        "dr0", "dr1", "dr2", "dr3", "dr6", "dr7", "mxcsr",
    ])?;

    assert!(
        regs.insert("rflags", dbg.reg64("efl")?).is_none(),
        "efl shouldn't be in regs"
    );

    let fptw = fptw(dbg.reg64("fptw")?);
    assert!(
        regs.insert("fptw", fptw).is_none(),
        "fptw shouldn't be in regs"
    );

    // While looking into `dbgeng.dll` I found an array that gives the registers /
    // indices for each of the supported platforms. The relevant one for 64-bit
    // Intel is called `struct REGDEF near * g_Amd64Defs`. As far as I can tell,
    // there's no mechanism available to dump @fpip / @fpipsel / @fpdp / @fpdpsel
    // registers :-/... so we'll set it to zero.
    assert!(
        regs.insert("fpop", 0).is_none(),
        "fpop shouldn't be in regs"
    );

    assert!(
        regs.insert("fpip", 0).is_none(),
        "fpip shouldn't be in regs"
    );

    assert!(
        // Default value from linux kernel (stolen from `bdump.js`'s code):
        //   https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/fpu/init.c#L117
        regs.insert("mxcsr_mask", 0xffbf).is_none(),
        "mxcsr_mask shouldn't be in regs"
    );

    let fpst = dbg
        .regs128(&["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"])?
        .into_iter()
        .map(Float80::from)
        .collect();

    let mut msrs = HashMap::from([
        ("tsc", msr::TSC),
        ("apic_base", msr::APIC_BASE),
        ("sysenter_cs", msr::SYSENTER_CS),
        ("sysenter_esp", msr::SYSENTER_ESP),
        ("sysenter_eip", msr::SYSENTER_EIP),
        ("pat", msr::PAT),
        ("efer", msr::EFER),
        ("star", msr::STAR),
        ("lstar", msr::LSTAR),
        ("cstar", msr::CSTAR),
        ("sfmask", msr::SFMASK),
        ("kernel_gs_base", msr::KERNEL_GS_BASE),
        ("tsc_aux", msr::TSC_AUX),
    ])
    .into_iter()
    .map(|(name, msr)| Ok((name, dbg.msr(msr)?)))
    .collect::<Result<HashMap<_, _>>>()?;

    let gdt = GlobalSeg::from(dbg.regs64(&["gdtr", "gdtl"])?);
    let idt = GlobalSeg::from(dbg.regs64(&["idtr", "idtl"])?);

    let selectors = dbg.regs64_dict(&["es", "cs", "ss", "ds", "tr", "gs", "fs", "ldtr"])?;
    let mut segs = selectors
        .into_iter()
        .map(|(name, selector)| Ok((name, dbg.gdt_entry(gdt.base, gdt.limit, selector)?)))
        .collect::<Result<HashMap<_, _>>>()?;

    // Fix up @gs / @fs base with the appropriate MSRs.
    let mut gs_base = dbg.msr(msr::GS_BASE)?;
    segs.get_mut("gs").unwrap().base = gs_base;
    segs.get_mut("fs").unwrap().base = dbg.msr(msr::FS_BASE)?;

    let rip = *regs.get("rip").unwrap();
    let gs = segs.get_mut("gs").unwrap();
    let mode_matches = is_usermode_addr(rip) == is_usermode_addr(gs.base);
    if !mode_matches {
        let kernel_gs_base = msrs.get_mut("kernel_gs_base").unwrap();
        mem::swap(&mut gs_base, kernel_gs_base);
        segs.get_mut("gs").unwrap().base = gs_base;
    }

    // Fix up @cr8 if it isn't zero and the debugger is currently stopped in
    // user-mode.
    let cr8 = regs.get_mut("cr8").unwrap();
    if is_usermode_addr(rip) && *cr8 != 0 {
        *cr8 = 0;
    }

    let gsegs = HashMap::from([("gdtr", gdt), ("idtr", idt)]);
    let sse = dbg
        .regs128_dict(&[
            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
            "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
        ])?
        .into_iter()
        .map(|(k, v)| (k, Zmm::from(v)))
        .collect();

    let generated_by = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    Ok(State {
        regs,
        segs,
        gsegs,
        fpst,
        msrs,
        sse,
        generated_by,
    })
}

/// This is where the meat is - this function generates the `state` folder made
/// of the CPU register as well as the memory dump.
fn snapshot_with_kind_inner(kind: SnapshotKind, dbg: &DebugClient, args: String) -> Result<()> {
    // Let's make sure this is a live kernel, not a dump, etc..
    let is_live_kernel = matches!(
        dbg.debuggee_type()?,
        (
            DEBUG_CLASS_KERNEL,
            DEBUG_KERNEL_EXDI_DRIVER | DEBUG_KERNEL_LOCAL | DEBUG_KERNEL_CONNECTION
        )
    );

    if !is_live_kernel {
        bail!("expected a live kernel debugging session");
    }

    // ... and the target is an x64 architecture..
    let is_intel64 = matches!(dbg.processor_type()?, IMAGE_FILE_MACHINE_AMD64);
    if !is_intel64 {
        bail!("expected an Intel 64-bit guest target");
    }

    // ... and the amount of processors of the target.
    if dbg.processor_number()? > 1 {
        bail!("expected to have only one core to dump the state of");
    }

    // Build the state path.
    let state_path = if args.is_empty() {
        env::temp_dir()
    } else {
        PathBuf::from(args)
    };

    if !state_path.exists() {
        bail!("the directory {:?} doesn't exist", state_path);
    }

    let state_path = state_path.join(gen_state_folder_name(dbg)?);
    if !state_path.exists() {
        fs::create_dir(&state_path)?;
    }

    // Build the `regs.json` / `mem.dmp` path.
    let regs_path = state_path.join("regs.json");
    let mem_path = state_path.join("mem.dmp");

    if regs_path.exists() {
        bail!("{:?} already exists", regs_path);
    }

    if mem_path.exists() {
        bail!("{:?} already exists", mem_path);
    }

    // All right, let's get to work now. First, grab the CPU state.
    let state = state(dbg)?;

    // Turn the state into a JSON value.
    let mut json = serde_json::to_value(state)?;

    // Walk a JSON `Value` and turn every `Number` into a `String`.
    // This is useful to turn every integer in your JSON document into an hex
    // encoded string.
    fn fix_number_nodes(v: &mut serde_json::Value) {
        match v {
            Value::Number(n) => *v = Value::String(format!("{:#x}", n.as_u64().unwrap())),
            Value::Array(a) => a.iter_mut().for_each(fix_number_nodes),
            Value::Object(o) => o.values_mut().for_each(fix_number_nodes),
            _ => {}
        }
    }

    fix_number_nodes(&mut json);

    // Dump the CPU register into a `regs.json` file.
    dbg.logln(format!(
        "Dumping the CPU state into {}..",
        regs_path.display()
    ))?;

    let regs_file = File::create(regs_path)?;
    serde_json::to_writer_pretty(regs_file, &json)?;

    dbg.logln(format!(
        "Dumping the memory state into {}..",
        mem_path.display()
    ))?;

    // Generate the `mem.dmp`.
    dbg.exec(format!(
        ".dump /{} {:?}",
        match kind {
            // Create a dump with active kernel and user mode memory.
            SnapshotKind::ActiveKernel => "ka",
            // A Complete Memory Dump is the largest kernel-mode dump file. This file includes all
            // of the physical memory that is used by Windows. A complete memory dump does not, by
            // default, include physical memory that is used by the platform firmware.
            SnapshotKind::Full => "f",
        },
        mem_path
    ))?;

    dbg.logln("Done!")?;

    Ok(())
}

/// This is a wrapper function made to be able to display the error in case the
/// inner function fails.
fn snapshot_with_kind(kind: SnapshotKind, client: IUnknown, args: PCSTR) -> HRESULT {
    let Ok(dbg) = DebugClient::new(client) else {
        return E_ABORT;
    };

    let Ok(args) = (unsafe { args.to_string() }) else {
        return E_ABORT;
    };

    match snapshot_with_kind_inner(kind, &dbg, args) {
        Err(e) => {
            dbg.logln(format!("Ran into an error: {e:?}")).unwrap();

            E_ABORT
        }
        Ok(_) => S_OK,
    }
}

#[no_mangle]
extern "C" fn snapshot(client: IUnknown, args: PCSTR) -> HRESULT {
    snapshot_with_kind(SnapshotKind::Full, client, args)
}

#[no_mangle]
extern "C" fn snapshot_full(client: IUnknown, args: PCSTR) -> HRESULT {
    snapshot_with_kind(SnapshotKind::Full, client, args)
}

#[no_mangle]
extern "C" fn snapshot_active_kernel(client: IUnknown, args: PCSTR) -> HRESULT {
    snapshot_with_kind(SnapshotKind::ActiveKernel, client, args)
}

/// The DebugExtensionInitialize callback function is called by the engine after
/// loading a DbgEng extension DLL. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nc-dbgeng-pdebug_extension_initialize
#[no_mangle]
extern "C" fn DebugExtensionInitialize(_version: *mut u32, _flags: *mut u32) -> HRESULT {
    S_OK
}

#[no_mangle]
extern "C" fn DebugExtensionUninitialize() {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    #[test]
    fn fptw() {
        let expected = BTreeMap::from([
            (0b00000000, 0b1111111111111111),
            (0b10000000, 0b0011111111111111),
            (0b11000000, 0b0000111111111111),
            (0b11100000, 0b0000001111111111),
            (0b11110000, 0b0000000011111111),
            (0b11111000, 0b0000000000111111),
            (0b11111100, 0b0000000000001111),
            (0b11111110, 0b0000000000000011),
            (0b11111111, 0b0000000000000000),
        ]);

        for (windbg, expected_fptw) in expected {
            let fptw = super::fptw(windbg);
            assert_eq!(
                fptw, expected_fptw,
                "fptw({}) returned {} instead of expect {}",
                windbg, fptw, expected_fptw
            );
        }
    }
}
