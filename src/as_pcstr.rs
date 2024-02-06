// Axel '0vercl0k' Souchet - January 21 2024
use std::ffi::CString;

use windows::core::PCSTR;

pub trait AsPCSTR {
    fn as_pcstr(&self) -> PCSTR;
}

impl AsPCSTR for CString {
    fn as_pcstr(&self) -> PCSTR {
        PCSTR::from_raw(self.as_ptr().cast())
    }
}
