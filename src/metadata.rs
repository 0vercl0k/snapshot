// Axel '0vercl0k' Souchet - September 1 2025

use std::{
    ffi::{CStr, CString},
    fmt::Display,
    mem,
    path::PathBuf,
    ptr,
};

use anyhow::{Result, bail};
use dbgeng::as_pcstr::AsPCSTR;
use serde::Serialize;
use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, HMODULE, MAX_PATH},
        Storage::FileSystem::{
            GetFileVersionInfoA, GetFileVersionInfoSizeA, VS_FIXEDFILEINFO, VerQueryValueA,
        },
        System::LibraryLoader::{GetModuleFileNameA, GetModuleHandleA},
    },
    core::{PCSTR, s},
};

/// The product version of a DLL.
#[derive(Debug, Default, Serialize)]
pub struct ProductVersion {
    major: u16,
    minor: u16,
    build: u16,
    revision: u16,
}

impl ProductVersion {
    fn new(fileinfo: &VS_FIXEDFILEINFO) -> Self {
        let v: u64 =
            ((fileinfo.dwProductVersionMS as u64) << 32) | fileinfo.dwProductVersionLS as u64;

        Self {
            major: (v >> 48) as u16,
            minor: (v >> 32) as u16,
            build: (v >> 16) as u16,
            revision: v as u16,
        }
    }
}

impl Display for ProductVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

pub fn get_module_handle(name: &str) -> Option<HMODULE> {
    let cstr = CString::new(name).expect("not a cstring");

    unsafe { GetModuleHandleA(cstr.as_pcstr()) }.ok()
}

#[derive(Debug, Serialize)]
pub struct DllInfo {
    path: PathBuf,
    version: ProductVersion,
}

impl DllInfo {
    pub fn new(module: HMODULE) -> Result<Self> {
        /// Get the full path of where the module is loaded from on disk.
        let mut buffer = vec![0u8; MAX_PATH as usize];
        let len = unsafe { GetModuleFileNameA(module, &mut buffer) };
        if len == 0 {
            bail!("GetModuleFileNameA failed");
        }

        if unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER {
            bail!("GetModuleFileNameA failed because buffer too small");
        }

        // Figure out the size of the file version info..
        let len_with_null = len + 1;
        let path_cstr = CStr::from_bytes_with_nul(&buffer[..len_with_null as usize])?;
        let path_pcstr = PCSTR::from_raw(path_cstr.as_ptr().cast());
        let vinfo_len = unsafe { GetFileVersionInfoSizeA(path_pcstr, None) };
        if vinfo_len == 0 {
            bail!("GetFileVersionInfoSizeA failed");
        }

        // ..and retrieve it.
        let mut vinfo = vec![0u8; vinfo_len as usize];
        if unsafe { GetFileVersionInfoA(path_pcstr, 0, vinfo_len, vinfo.as_mut_ptr().cast()) }
            .is_err()
        {
            bail!("GetFileVersionInfoA failed");
        }

        // Now, let's figure out where the VS_FIXEDFILEINFO is.
        let mut fileinfo: *mut VS_FIXEDFILEINFO = ptr::null_mut();
        let mut fileinfo_len = 0u32;
        if !unsafe {
            VerQueryValueA(
                vinfo.as_ptr().cast(),
                s!("\\"),
                &mut fileinfo as *mut _ as *mut _,
                &mut fileinfo_len,
            )
        }
        .as_bool()
        {
            bail!("VerQueryValueA failed");
        }

        // If the size is too small, bail out.
        if fileinfo_len < mem::size_of::<VS_FIXEDFILEINFO>() as u32 {
            bail!("VerQueryValueA returned too small VS_FIXEDFILEINFO");
        }

        // Finally, read the file info and the version.
        let fileinfo = unsafe { fileinfo.read_unaligned() };
        debug_assert!(fileinfo.dwSignature == 0xFE_EF_04_BD);
        let version = ProductVersion::new(&fileinfo);

        // Get the DLL path ready for a Rust [`String`] by getting rid of the null terminator.
        buffer.truncate(len as usize);
        let path = PathBuf::from(String::from_utf8(buffer)?);

        Ok(Self { path, version })
    }
}

#[derive(Debug, Serialize)]
pub struct Metadata {
    pub debug_dlls: Vec<DllInfo>,
}
