/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Common ELF utilities shared across PHP, V8/Node.js, and Python interpreters.
//!
//! This module provides a unified `MappedFile` abstraction for:
//! - Loading ELF binary files
//! - Parsing symbols (static and dynamic)
//! - Computing base addresses for relocated binaries
//! - Finding .text section program headers

use std::{
    fs,
    path::{Path, PathBuf},
};

use log::{debug, trace};
use object::{
    elf,
    read::elf::{FileHeader, ProgramHeader, SectionHeader},
    Object, ObjectSymbol,
};

use crate::error::Result;

/// A memory-mapped ELF file with lazy loading and symbol lookup capabilities.
///
/// This struct is used by PHP, V8/Node.js, and Python interpreters to:
/// - Load binary contents on demand
/// - Search for symbols in static and dynamic symbol tables
/// - Calculate base addresses for position-independent code
pub struct MappedFile {
    /// Path to the ELF file
    pub path: PathBuf,
    /// Lazily loaded file contents
    pub contents: Vec<u8>,
    /// Memory start address from /proc/PID/maps
    pub mem_start: u64,
}

impl MappedFile {
    /// Create a new MappedFile with the given path and memory start address.
    pub fn new(path: impl Into<PathBuf>, mem_start: u64) -> Self {
        Self {
            path: path.into(),
            contents: Vec::new(),
            mem_start,
        }
    }

    /// Create a new MappedFile from a string path.
    pub fn from_str(path: &str, mem_start: u64) -> Self {
        Self::new(PathBuf::from(path), mem_start)
    }

    /// Load file contents lazily. Only reads from disk on first call.
    pub fn load(&mut self) -> Result<()> {
        if self.contents.is_empty() {
            self.contents = fs::read(&self.path)?;
        }
        Ok(())
    }

    /// Check if the loaded binary contains any of the specified symbols.
    ///
    /// This searches both static (.symtab) and dynamic (.dynsym) symbol tables.
    /// Used for runtime detection (e.g., detecting PHP, Node.js, Python processes).
    pub fn has_any_symbols(&mut self, symbols: &[&str]) -> Result<bool> {
        self.load()?;
        let obj = object::File::parse(&*self.contents)?;
        Ok(obj.symbols().chain(obj.dynamic_symbols()).any(|s| {
            if let Ok(name) = s.name() {
                for sym in symbols {
                    if &name == sym {
                        return true;
                    }
                }
            }
            false
        }))
    }

    /// Check if the loaded binary contains any symbols matching by prefix or containing substring.
    ///
    /// This is useful for V8 which has versioned symbols like "v8dbg_type_JSFunction".
    pub fn has_any_symbols_matching(&mut self, symbols: &[&str]) -> Result<bool> {
        self.load()?;
        let obj = object::File::parse(&*self.contents)?;
        Ok(obj.symbols().chain(obj.dynamic_symbols()).any(|s| {
            if let Ok(name) = s.name() {
                for sym in symbols {
                    if &name == sym || name.contains(sym) {
                        return true;
                    }
                }
            }
            false
        }))
    }

    /// Find the program header containing the .text section.
    ///
    /// This is used to calculate the base address offset for position-independent
    /// executables (PIE) and shared libraries.
    pub fn find_text_section_program_header<P: AsRef<Path>>(
        path: P,
        data: &[u8],
    ) -> Result<Option<&elf::ProgramHeader64<object::Endianness>>> {
        let elf = elf::FileHeader64::<object::Endianness>::parse(data)?;
        let endian = elf.endian()?;
        let sec_headers = elf.section_headers(endian, data)?;
        let sec_strs = elf.section_strings(endian, data, sec_headers)?;
        let Some(th) = sec_headers
            .iter()
            .find(|h| h.name(endian, sec_strs) == Ok(".text".as_bytes()))
        else {
            debug!("Cannot find .text section in {}", path.as_ref().display());
            return Ok(None);
        };
        for ph in elf.program_headers(endian, data)? {
            if ph.p_type(endian) == elf::PT_LOAD && ph.p_flags(endian) & elf::PF_X != 0 {
                let th_addr = th.sh_addr(endian);
                let ph_vaddr = ph.p_vaddr(endian);
                let ph_memsz = ph.p_memsz(endian);
                if th_addr >= ph_vaddr && th_addr < ph_vaddr + ph_memsz {
                    return Ok(Some(ph));
                }
            }
        }
        trace!(
            "Cannot find .text section program header in {}",
            path.as_ref().display()
        );
        Ok(None)
    }

    /// Calculate the base address for symbol address computation.
    ///
    /// For position-independent code, symbols need to be offset by the difference
    /// between the memory mapping start and the virtual address in the ELF file.
    pub fn base_address(&mut self) -> Result<u64> {
        self.load()?;
        let elf = elf::FileHeader64::<object::Endianness>::parse(&*self.contents)?;
        let endian = elf.endian()?;
        let Some(ph) = Self::find_text_section_program_header(&self.path, &*self.contents)? else {
            return Ok(self.mem_start);
        };
        Ok(self.mem_start.saturating_sub(ph.p_vaddr(endian)))
    }

    /// Find the runtime address of a symbol by name.
    ///
    /// Returns the symbol's virtual address plus the base address offset.
    pub fn find_symbol_address(&mut self, name: &str) -> Result<Option<u64>> {
        self.load()?;
        let ba = self.base_address()?;
        let obj = object::File::parse(&*self.contents)?;
        Ok(obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == name).unwrap_or(false))
            .map(|s| s.address() + ba))
    }

    /// Find the runtime address range (start, end-exclusive) of a symbol.
    ///
    /// The end address is determined by finding the next symbol in sorted order.
    /// If no next symbol is found, a conservative fallback size is used.
    pub fn find_symbol_range(&mut self, name: &str) -> Result<Option<(u64, u64)>> {
        self.load()?;
        let ba = self.base_address()?;
        let obj = object::File::parse(&*self.contents)?;

        let mut syms: Vec<_> = obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .filter(|s| s.address() != 0 && s.name().map(|n| !n.is_empty()).unwrap_or(false))
            .collect();
        syms.sort_by_key(|s| s.address());

        let pos = syms
            .iter()
            .position(|s| s.name().map(|n| n == name).unwrap_or(false));
        let Some(idx) = pos else { return Ok(None) };
        let start = syms[idx].address() + ba;
        let end = syms
            .get(idx + 1)
            .map(|s| s.address() + ba)
            .unwrap_or(start + 0x2000); // conservative fallback if size is unknown
        Ok(Some((start, end)))
    }

    /// Get the file name without path.
    pub fn file_name(&self) -> Option<&str> {
        self.path.file_name().and_then(|s| s.to_str())
    }

    /// Check if the file name contains a substring.
    pub fn file_name_contains(&self, pattern: &str) -> bool {
        self.file_name()
            .map(|s| s.contains(pattern))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapped_file_new() {
        let mf = MappedFile::new("/path/to/file", 0x1000);
        assert_eq!(mf.path.to_str().unwrap(), "/path/to/file");
        assert_eq!(mf.mem_start, 0x1000);
        assert!(mf.contents.is_empty());
    }

    #[test]
    fn test_mapped_file_from_str() {
        let mf = MappedFile::from_str("/path/to/file", 0x2000);
        assert_eq!(mf.path.to_str().unwrap(), "/path/to/file");
        assert_eq!(mf.mem_start, 0x2000);
    }

    #[test]
    fn test_file_name() {
        let mf = MappedFile::new("/usr/bin/php8.1", 0);
        assert_eq!(mf.file_name(), Some("php8.1"));
    }

    #[test]
    fn test_file_name_contains() {
        let mf = MappedFile::new("/usr/bin/php8.1-fpm", 0);
        assert!(mf.file_name_contains("php"));
        assert!(mf.file_name_contains("fpm"));
        assert!(!mf.file_name_contains("python"));
    }
}
