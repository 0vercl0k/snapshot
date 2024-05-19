// Axel '0vercl0k' Souchet - January 21 2024
use std::collections::HashMap;

use dbgeng::client::Seg;
use serde::Serialize;

#[derive(Default, Debug, Serialize)]
pub struct Zmm([u64; 8]);

impl From<u128> for Zmm {
    fn from(value: u128) -> Self {
        let q0 = u64::try_from(value & 0xff_ff_ff_ff_ff_ff_ff_ff).unwrap();
        let q1 = u64::try_from(value >> 64).unwrap();

        Zmm([q0, q1, 0, 0, 0, 0, 0, 0])
    }
}

#[derive(Default, Debug, Serialize)]
pub struct GlobalSeg {
    pub base: u64,
    pub limit: u16,
}

impl From<Vec<u64>> for GlobalSeg {
    fn from(value: Vec<u64>) -> Self {
        assert!(
            value.len() == 2,
            "the vector should have the base and the limit"
        );

        Self {
            base: value[0],
            limit: value[1] as u16,
        }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct Float80 {
    fraction: u64,
    exp: u16,
}

impl From<u128> for Float80 {
    fn from(value: u128) -> Self {
        let fraction = (value & 0xff_ff_ff_ff_ff_ff_ff_ff).try_into().unwrap();
        let exp = ((value >> 64) & 0xff_ff).try_into().unwrap();

        Self { fraction, exp }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct State<'a> {
    #[serde(flatten)]
    pub regs: HashMap<&'a str, u64>,

    #[serde(flatten)]
    pub segs: HashMap<&'a str, Seg>,

    #[serde(flatten)]
    pub gsegs: HashMap<&'a str, GlobalSeg>,

    #[serde(flatten)]
    pub sse: HashMap<&'a str, Zmm>,

    pub fpst: Vec<Float80>,

    #[serde(flatten)]
    pub msrs: HashMap<&'a str, u64>,

    pub generated_by: String,
}
