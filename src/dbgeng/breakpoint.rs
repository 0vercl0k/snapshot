use std::ffi::{CStr, CString};

use anyhow::{Context, Result};
use bitflags::bitflags;
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    IDebugBreakpoint, DEBUG_BREAKPOINT_ADDER_ONLY, DEBUG_BREAKPOINT_DEFERRED,
    DEBUG_BREAKPOINT_ENABLED, DEBUG_BREAKPOINT_GO_ONLY, DEBUG_BREAKPOINT_ONE_SHOT,
    DEBUG_BREAKPOINT_PARAMETERS,
};

use crate::as_pcstr::AsPCSTR;

bitflags! {
    pub struct BreakpointFlags: u32 {
        const NONE = 0;
        const ENABLED = DEBUG_BREAKPOINT_ENABLED;
        const ADDER_ONLY = DEBUG_BREAKPOINT_ADDER_ONLY;
        const ONE_SHOT = DEBUG_BREAKPOINT_ONE_SHOT;
        const GO_ONLY = DEBUG_BREAKPOINT_GO_ONLY;
        /// Breakpoint deferred until symbols are loaded. This flag cannot be set or changed.
        const DEFERRED = DEBUG_BREAKPOINT_DEFERRED;
    }

}

pub enum BreakpointType {
    Code,
    Data,
}

/// A DbgEng breakpoint.
///
/// Typically to setup a breakpoint, you will want to set the offset
/// or offset expression and then set the `BreakpointFlags::ENABLED` flag.
pub struct DebugBreakpoint(IDebugBreakpoint);

impl DebugBreakpoint {
    pub fn new(bp: IDebugBreakpoint) -> Self {
        Self(bp)
    }

    /// The unique breakpoint ID. As long as this breakpoint is active, this
    /// ID will uniquely refer to this breakpoint.
    pub fn id(&self) -> Result<u32> {
        let id = unsafe { self.0.GetId() }?;
        Ok(id)
    }

    pub fn command(&self) -> Result<String> {
        let mut params = DEBUG_BREAKPOINT_PARAMETERS::default();
        unsafe { self.0.GetParameters(&mut params) }
            .context("failed to get breakpoint parameters")?;

        let mut buf = vec![0u8; params.CommandSize as usize];
        let mut len = buf.len() as u32;
        unsafe { self.0.GetOffsetExpression(Some(&mut buf), Some(&mut len)) }
            .context("failed to get breakpoint command")?;

        // Should always be equal...
        assert_eq!(len, params.CommandSize);

        let s = CStr::from_bytes_with_nul(&buf)
            .expect("dbgeng returned invalid command string") // This shouldn't fail.
            .to_str()
            .context("failed to convert breakpoint command to string")?;

        Ok(s.to_owned())
    }

    pub fn set_command<S: Into<String>>(&self, command: S) -> Result<()> {
        let cstr = CString::new(command.into())?;
        unsafe { self.0.SetCommand(cstr.as_pcstr()) }
            .with_context(|| format!("failed to set breakpoint command to {cstr:?}"))
    }

    pub fn flags(&self) -> Result<BreakpointFlags> {
        let flags = unsafe { self.0.GetFlags() }.context("failed to get breakpoint flags")?;

        BreakpointFlags::from_bits(flags)
            .with_context(|| format!("could not convert flags from {flags:#010X}"))
    }

    pub fn set_flags(&self, flags: BreakpointFlags) -> Result<()> {
        unsafe { self.0.SetFlags(flags.bits()) }
            .with_context(|| format!("failed to set breakpoint flags to {flags:#010X}"))
    }

    pub fn offset_expression(&self) -> Result<String> {
        let mut params = DEBUG_BREAKPOINT_PARAMETERS::default();
        unsafe { self.0.GetParameters(&mut params) }
            .context("failed to get breakpoint parameters")?;

        let mut buf = vec![0u8; params.OffsetExpressionSize as usize];
        let mut len = buf.len() as u32;
        unsafe { self.0.GetOffsetExpression(Some(&mut buf), Some(&mut len)) }
            .context("failed to get breakpoint offset expression")?;

        // Should always be equal...
        assert_eq!(len, params.OffsetExpressionSize);

        let s = CStr::from_bytes_with_nul(&buf)
            .expect("dbgeng returned invalid offset expression string") // This shouldn't fail.
            .to_str()
            .context("failed to convert breakpoint offset expression to string")?;

        Ok(s.to_owned())
    }

    pub fn set_offset_expression<S: Into<String>>(&self, e: S) -> Result<()> {
        let s: String = e.into();
        let cstr = CString::new(s.clone())?;
        unsafe { self.0.SetOffsetExpression(cstr.as_pcstr()) }
            .with_context(|| format!("failed to set breakpoint offset expression to {s}"))
    }

    pub fn offset(&self) -> Result<u64> {
        unsafe { self.0.GetOffset() }.context("failed to get breakpoint offset")
    }

    pub fn set_offset(&self, offset: u64) -> Result<()> {
        unsafe { self.0.SetOffset(offset) }
            .with_context(|| format!("failed to set breakpoint offset to {offset:#018X}"))
    }
}
