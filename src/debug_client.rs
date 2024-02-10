// Axel '0vercl0k' Souchet - January 21 2024
use std::collections::HashMap;
use std::ffi::CString;

use anyhow::{bail, Context, Result};
use windows::core::{ComInterface, IUnknown};
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    IDebugControl3, IDebugDataSpaces4, IDebugRegisters, IDebugSymbols, DEBUG_EXECUTE_DEFAULT,
    DEBUG_OUTCTL_ALL_CLIENTS, DEBUG_OUTPUT_NORMAL, DEBUG_VALUE, DEBUG_VALUE_FLOAT128,
    DEBUG_VALUE_FLOAT32, DEBUG_VALUE_FLOAT64, DEBUG_VALUE_FLOAT80, DEBUG_VALUE_INT16,
    DEBUG_VALUE_INT32, DEBUG_VALUE_INT64, DEBUG_VALUE_INT8, DEBUG_VALUE_VECTOR128,
    DEBUG_VALUE_VECTOR64,
};
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE;

use crate::as_pcstr::AsPCSTR;
use crate::bits::Bits;
use crate::state::Seg;

/// Extract `u128` off a `DEBUG_VALUE`.
pub fn u128_from_debugvalue(v: DEBUG_VALUE) -> Result<u128> {
    let value = match v.Type {
        DEBUG_VALUE_FLOAT80 => {
            let f80 = unsafe { v.Anonymous.F80Bytes };
            let mut bytes = [0; 16];
            bytes[0..10].copy_from_slice(&f80);

            u128::from_le_bytes(bytes)
        }
        DEBUG_VALUE_VECTOR128 => u128::from_le_bytes(unsafe { v.Anonymous.VI8 }),
        DEBUG_VALUE_FLOAT128 => u128::from_le_bytes(unsafe { v.Anonymous.F128Bytes }),
        _ => {
            bail!("expected float128 values, but got Type={:#x}", v.Type);
        }
    };

    Ok(value)
}

/// Extract a `u64/u32/u16/u8/f64` off a DEBUG_VALUE.
pub fn u64_from_debugvalue(v: DEBUG_VALUE) -> Result<u64> {
    let value = match v.Type {
        DEBUG_VALUE_INT64 => {
            let parts = unsafe { v.Anonymous.I64Parts32 };

            (u64::from(parts.HighPart) << 32) | u64::from(parts.LowPart)
        }
        DEBUG_VALUE_INT32 => unsafe { v.Anonymous.I32 }.into(),
        DEBUG_VALUE_INT16 => unsafe { v.Anonymous.I16 }.into(),
        DEBUG_VALUE_INT8 => unsafe { v.Anonymous.I8 }.into(),
        DEBUG_VALUE_VECTOR64 => {
            u64::from_le_bytes(unsafe { &v.Anonymous.VI8[0..8] }.try_into().unwrap())
        }
        DEBUG_VALUE_FLOAT64 => unsafe { v.Anonymous.F64 }.to_bits(),
        DEBUG_VALUE_FLOAT32 => f64::from(unsafe { v.Anonymous.F32 }).to_bits(),
        _ => {
            bail!("expected int/float values, but got Type={:#x}", v.Type);
        }
    };

    Ok(value)
}

/// Macro to make it nicer to invoke `DebugClient::logln` / `DebugClient::log`
/// by avoiding to `format!` everytime the arguments.
#[macro_export]
macro_rules! dlogln {
    ($dbg:ident, $($arg:tt)*) => {{
        $dbg.logln(format!($($arg)*))
    }};
}

#[macro_export]
macro_rules! dlog {
    ($dbg:ident, $($arg:tt)*) => {{
        $dbg.log(format!($($arg)*))
    }};
}

pub struct DebugClient {
    control: IDebugControl3,
    registers: IDebugRegisters,
    dataspaces: IDebugDataSpaces4,
    symbols: IDebugSymbols,
}

impl DebugClient {
    pub fn new(client: &IUnknown) -> Result<Self> {
        let control = client.cast()?;
        let registers = client.cast()?;
        let dataspaces = client.cast()?;
        let symbols = client.cast()?;

        Ok(Self {
            control,
            registers,
            dataspaces,
            symbols,
        })
    }

    /// Output a message `s`.
    fn output<Str>(&self, mask: u32, s: Str) -> Result<()>
    where
        Str: Into<Vec<u8>>,
    {
        let cstr = CString::new(s.into())?;
        unsafe { self.control.Output(mask, cstr.as_pcstr()) }.context("Output failed")
    }

    /// Log a message in the debugging window.
    #[allow(dead_code)]
    pub fn log<Str>(&self, args: Str) -> Result<()>
    where
        Str: Into<Vec<u8>>,
    {
        self.output(DEBUG_OUTPUT_NORMAL, args)
    }

    /// Log a message followed by a new line in the debugging window.
    pub fn logln<Str>(&self, args: Str) -> Result<()>
    where
        Str: Into<Vec<u8>>,
    {
        self.output(DEBUG_OUTPUT_NORMAL, "[snapshot] ")?;
        self.output(DEBUG_OUTPUT_NORMAL, args)?;
        self.output(DEBUG_OUTPUT_NORMAL, "\n")
    }

    /// Execute a debugger command.
    pub fn exec<Str>(&self, cmd: Str) -> Result<()>
    where
        Str: Into<Vec<u8>>,
    {
        let cstr = CString::new(cmd.into())?;
        unsafe {
            self.control.Execute(
                DEBUG_OUTCTL_ALL_CLIENTS,
                cstr.as_pcstr(),
                DEBUG_EXECUTE_DEFAULT,
            )
        }
        .context(format!("Execute({:?}) failed", cstr))
    }

    /// Get the register indices from names.
    pub fn reg_indices(&self, names: &[&str]) -> Result<Vec<u32>> {
        let mut indices = Vec::with_capacity(names.len());
        for name in names {
            let indice = unsafe {
                self.registers
                    .GetIndexByName(CString::new(*name)?.as_pcstr())
            }
            .context(format!("GetIndexByName failed for {name}"))?;

            indices.push(indice);
        }

        Ok(indices)
    }

    /// Get the value of multiple registers.
    pub fn reg_values(&self, indices: &[u32]) -> Result<Vec<DEBUG_VALUE>> {
        let mut values = vec![DEBUG_VALUE::default(); indices.len()];
        unsafe {
            self.registers.GetValues(
                indices.len().try_into()?,
                Some(indices.as_ptr()),
                0,
                values.as_mut_ptr(),
            )
        }
        .context(format!("GetValues failed for {indices:?}"))?;

        Ok(values)
    }

    /// Get `u128` values for the registers identified by their names.
    pub fn regs128(&self, names: &[&str]) -> Result<Vec<u128>> {
        let indices = self.reg_indices(names)?;
        let values = self.reg_values(&indices)?;

        values.into_iter().map(u128_from_debugvalue).collect()
    }

    /// Get `u128` values for the registers identified by their names but
    /// returned in a dictionary with their names.
    pub fn regs128_dict<'a>(&self, names: &[&'a str]) -> Result<HashMap<&'a str, u128>> {
        let values = self.regs128(names)?;

        Ok(HashMap::from_iter(
            names.iter().zip(values).map(|(k, v)| (*k, v)),
        ))
    }

    /// Get the values of a set of registers identified by their names.
    pub fn regs64(&self, names: &[&str]) -> Result<Vec<u64>> {
        let indices = self.reg_indices(names)?;
        let values = self.reg_values(&indices)?;

        values.into_iter().map(u64_from_debugvalue).collect()
    }

    /// Get the values of a set of registers identified by their names and store
    /// both their names / values in a dictionary.
    pub fn regs64_dict<'a>(&self, names: &[&'a str]) -> Result<HashMap<&'a str, u64>> {
        let values = self.regs64(names)?;

        Ok(HashMap::from_iter(
            names.iter().zip(values).map(|(k, v)| (*k, v)),
        ))
    }

    /// Get the value of a register identified by its name.
    pub fn reg64(&self, name: &str) -> Result<u64> {
        let v = self.regs64(&[name])?;

        Ok(v[0])
    }

    /// Get the value of a specific MSR.
    pub fn msr(&self, msr: u32) -> Result<u64> {
        unsafe { self.dataspaces.ReadMsr(msr) }.context("ReadMsr failed")
    }

    /// Read a segment descriptor off the GDT.
    pub fn gdt_entry(&self, gdt_base: u64, gdt_limit: u16, selector: u64) -> Result<Seg> {
        // Let's first get the index out of the selector; here's what the selector looks
        // like (Figure 3-6. Segment Selector):
        //
        // 15                                                 3    2        0
        // +--------------------------------------------------+----+--------+
        // |          Index                                   | TI |   RPL  |
        // +--------------------------------------------------+----+--------+
        //
        // TI = Table Indicator: 0 = GDT, 1 = LDT
        //

        // The function will read the descriptor off the GDT, so let's make sure the
        // table indicator matches that.
        let ti = selector.bit(2);
        if ti != 0 {
            bail!("expected a GDT table indicator when reading segment descriptor");
        }

        // Extract the index so that we can calculate the address of the GDT entry.
        let index = selector.bits(3..=15);
        // 3.5.1 Segment Descriptor Tables
        // "As with segments, the limit value is added to the base address to get the
        // address of the last valid byte. A limit value of 0 results in exactly one
        // valid byte. Because segment descriptors are always 8 bytes long, the GDT
        // limit should always be one less than an integral multiple of eight (that is,
        // 8N – 1)"
        let gdt_limit = gdt_limit as u64;
        assert!((gdt_limit + 1) % 8 == 0);
        let max_index = (gdt_limit + 1) / 8;
        if index >= max_index {
            bail!("the selector {selector:#x} has an index ({index:#x}) larger than the maximum allowed ({max_index:#})");
        }

        // Most GDT entries are 8 bytes long but some are 16, so accounting for that.
        //
        // 3.5 SYSTEM DESCRIPTOR TYPES
        // "When the S (descriptor type) flag in a segment descriptor is clear, the
        // descriptor type is a system descriptor." "Note that system
        // descriptors in IA-32e mode are 16 bytes instead of 8 bytes."
        let mut descriptor = [0; 16];
        // 3.4.2 Segment Selectors
        // "The processor multiplies the index value by 8 (the number of bytes in a
        // segment descriptor).."
        let entry_addr = gdt_base + (index * 8u64);

        // Read the entry.
        self.read_virtual_exact(entry_addr, &mut descriptor)?;

        // Build the descriptor.
        Ok(Seg::from_descriptor(
            selector,
            u128::from_le_bytes(descriptor),
        ))
    }

    /// Read an exact amount of virtual memory.
    pub fn read_virtual_exact(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        let amount_read = self.read_virtual(vaddr, buf)?;
        if amount_read != buf.len() {
            bail!(
                "expected to read_virtual {:#x} bytes, but read {:#x}",
                buf.len(),
                amount_read
            );
        }

        Ok(())
    }

    /// Read virtual memory.
    pub fn read_virtual(&self, vaddr: u64, buf: &mut [u8]) -> Result<usize> {
        let mut amount_read = 0;
        unsafe {
            self.dataspaces.ReadVirtual(
                vaddr,
                buf.as_mut_ptr().cast(),
                buf.len().try_into()?,
                Some(&mut amount_read),
            )
        }
        .context("ReadVirtual failed")?;

        Ok(usize::try_from(amount_read)?)
    }

    /// Get the debuggee type.
    pub fn debuggee_type(&self) -> Result<(u32, u32)> {
        let mut class = 0;
        let mut qualifier = 0;
        unsafe { self.control.GetDebuggeeType(&mut class, &mut qualifier) }?;

        Ok((class, qualifier))
    }

    /// Get the processor type of the target.
    pub fn processor_type(&self) -> Result<IMAGE_FILE_MACHINE> {
        let proc_type = unsafe { self.control.GetActualProcessorType() }
            .context("GetActualProcessorType failed")?;

        Ok(IMAGE_FILE_MACHINE(proc_type.try_into()?))
    }

    /// Get the number of processors in the target.
    pub fn processor_number(&self) -> Result<u32> {
        unsafe { self.control.GetNumberProcessors() }.context("GetNumberProcessors failed")
    }

    /// Get an address for a named symbol.
    pub fn get_address_by_name<Str>(&self, symbol: Str) -> Result<u64>
    where
        Str: Into<Vec<u8>>,
    {
        let symbol_cstr = CString::new(symbol.into())?;

        unsafe { self.symbols.GetOffsetByName(symbol_cstr.as_pcstr()) }
            .context("GetOffsetByName failed")
    }

    /// Read a NULL terminated string at `addr`.
    pub fn read_cstring(&self, addr: u64) -> Result<String> {
        let maxbytes = 100;
        let mut buffer = vec![0; maxbytes];
        let mut length = 0;
        unsafe {
            self.dataspaces.ReadMultiByteStringVirtual(
                addr,
                maxbytes as u32,
                Some(buffer.as_mut()),
                Some(&mut length),
            )
        }?;

        if length == 0 {
            bail!("length is zero")
        }

        let length = length as usize;
        buffer.resize(length - 1, 0);

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }
}
