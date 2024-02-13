use std::ffi::CString;

use anyhow::{Context, Result};
use bitflags::bitflags;
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    IDebugBreakpoint, DEBUG_BREAKPOINT_ADDER_ONLY, DEBUG_BREAKPOINT_DEFERRED,
    DEBUG_BREAKPOINT_ENABLED, DEBUG_BREAKPOINT_GO_ONLY, DEBUG_BREAKPOINT_ONE_SHOT,
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

pub struct DebugBreakpoint(IDebugBreakpoint);

impl DebugBreakpoint {
    pub fn new(bp: IDebugBreakpoint) -> Self {
        Self(bp)
    }

    pub fn id(&self) -> Result<u32> {
        let id = unsafe { self.0.GetId() }?;
        Ok(id)
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
}
