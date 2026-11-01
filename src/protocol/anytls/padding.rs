// SPDX-License-Identifier: GPL-3.0-only
//! Bounded server padding advertisement. MD5 identifies a public policy; it is
//! not used for authentication or encryption.
use md5::{Digest, Md5};
use std::collections::BTreeSet;
pub const DEFAULT: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
pub struct Scheme {
    pub raw: String,
    pub md5: String,
}
impl Scheme {
    pub fn parse(raw: &str) -> Result<Self, crate::runtime::Error> {
        let raw = if raw.is_empty() { DEFAULT } else { raw };
        let invalid = crate::runtime::Error::Preparation("AnyTLS padding scheme");
        if raw.len() > 16384 {
            return Err(invalid);
        }
        let mut stop = None;
        let mut names = BTreeSet::new();
        let mut records = Vec::new();
        for line in raw.lines() {
            let (name, value) = line.split_once('=').ok_or_else(|| invalid.clone())?;
            if !names.insert(name) {
                return Err(invalid);
            }
            if name == "stop" {
                let n = value.parse::<u32>().map_err(|_| invalid.clone())?;
                if n == 0 || n > 64 {
                    return Err(invalid);
                }
                stop = Some(n);
                continue;
            }
            let index = name.parse::<u32>().map_err(|_| invalid.clone())?;
            records.push(index);
            if value.split(',').count() > 32 {
                return Err(invalid);
            }
            for range in value.split(',') {
                if range == "c" {
                    continue;
                }
                let (a, b) = range.split_once('-').ok_or_else(|| invalid.clone())?;
                let a = a.parse::<u32>().map_err(|_| invalid.clone())?;
                let b = b.parse::<u32>().map_err(|_| invalid.clone())?;
                if a == 0 || b == 0 || a > 65535 || b > 65535 {
                    return Err(invalid);
                }
            }
        }
        let stop = stop.ok_or_else(|| invalid.clone())?;
        if records.iter().any(|index| *index >= stop) {
            return Err(invalid);
        }
        Ok(Self {
            raw: raw.to_owned(),
            md5: format!("{:x}", Md5::digest(raw.as_bytes())),
        })
    }
}
