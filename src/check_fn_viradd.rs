use std::fs::read;
use std::env::args;
use std::char::from_u32;
use std::mem::transmute;
use std::mem::size_of;

use rustc_demangle::{try_demangle, Demangle, TryDemangleError};

pub fn check_fn_vir_address(file_path: &str, sym_name: &str) {
    let file = match read(file_path) {
        Ok(file) => file,
        Err(e) => {
            panic!("{:?}", e);
        }
    };
    let mut array: [u8; size_of::<EIdent>()] = [0x0; size_of::<EIdent>()];
    for idx in 0..size_of::<EIdent>() {
        // println!("{:?}", from_u32(file[idx as usize] as u32));
        array[idx] = file[idx as usize];
    }
    let e_ident: EIdent = unsafe { transmute::<[u8; size_of::<EIdent>()], EIdent>(array) };
    // println!("{:?}", e_ident);
    // println!("{:?}", e_ident.check_elf_format());
    if e_ident.check_elf_format().is_err() || !e_ident.check_elf_format().unwrap() { panic!("{:?} is not elf format!!", file_path); }

    let mut array: [u8; size_of::<ElfEhdr>()] = [0x0; size_of::<ElfEhdr>()];
    for (idx, b) in file.iter().enumerate().take(size_of::<ElfEhdr>()) {
        // println!("{:?}", b);
        array[idx] = b.clone();
    }
    let elf_ehdr: ElfEhdr = unsafe { transmute::<[u8; size_of::<ElfEhdr>()], ElfEhdr>(array) };
    // println!("elf_ehdr: {:?}", elf_ehdr);

    for idx in 0..elf_ehdr.e_phnum {
        let elf_ephdr: ElfEPhdr = ElfEPhdr::parse_unit(&file, &elf_ehdr, idx as usize);
        // println!("プログラムヘッダー, idx: {:?}, elf_ephdr: {:?}", idx, elf_ephdr);
    }

    let mut elf_ehdr_list: Vec<ElfEShdr> = vec![];
    for idx in 0..elf_ehdr.e_shnum {
        let elf_eshdr: ElfEShdr = ElfEShdr::parse_unit(&file, &elf_ehdr, idx as usize);
        // println!("セクションヘッダー, idx: {:?}, elf_eshdr: {:?}, Type: {:?}", idx, elf_eshdr, elf_eshdr.get_type());
        elf_ehdr_list.push(elf_eshdr);
    }
    let var_addr_map = match lookup_sym_name(&file, &elf_ehdr_list, sym_name) {
        Ok(Some(addr)) => addr,
        _ =>  panic!("{:?} is nothing.")
    };
    println!("{:?}", var_addr_map);
}

pub fn get_fn_vir_address_maps(file_path: &str) -> Vec<SymMap> {
    let file = match read(file_path) {
        Ok(file) => file,
        Err(e) => {
            panic!("{:?}", e);
        }
    };
    let mut array: [u8; size_of::<EIdent>()] = [0x0; size_of::<EIdent>()];
    for idx in 0..size_of::<EIdent>() {
        array[idx] = file[idx as usize];
    }
    let e_ident: EIdent = unsafe { transmute::<[u8; size_of::<EIdent>()], EIdent>(array) };
    if e_ident.check_elf_format().is_err() || !e_ident.check_elf_format().unwrap() { panic!("{:?} is not elf format!!", file_path); }

    let mut array: [u8; size_of::<ElfEhdr>()] = [0x0; size_of::<ElfEhdr>()];
    for (idx, b) in file.iter().enumerate().take(size_of::<ElfEhdr>()) {
        array[idx] = b.clone();
    }
    let elf_ehdr: ElfEhdr = unsafe { transmute::<[u8; size_of::<ElfEhdr>()], ElfEhdr>(array) };

    for idx in 0..elf_ehdr.e_phnum {
        let elf_ephdr: ElfEPhdr = ElfEPhdr::parse_unit(&file, &elf_ehdr, idx as usize);
    }

    let mut elf_ehdr_list: Vec<ElfEShdr> = vec![];
    for idx in 0..elf_ehdr.e_shnum {
        let elf_eshdr: ElfEShdr = ElfEShdr::parse_unit(&file, &elf_ehdr, idx as usize);
        elf_ehdr_list.push(elf_eshdr);
    }

    let var_addr_map = match get_all_sym_name_vir_addr_map(&file, &elf_ehdr_list) {
        Ok(addr) => addr,
        _ =>  panic!("{:?} is nothing.")
    };
    return var_addr_map;
}

#[derive(Debug)]
struct EIdent {
    magic_num1: u8,
    magic_str_e: u8,
    magic_str_l: u8,
    magic_str_f: u8,
    elf_class: u8,
    elf_endian: u8,
    elf_format_version: u8,
    os_abi: u8,
    os_abi_version: u8,
    padding: [u8; 6],
}

impl EIdent {
    pub fn check_elf_format(&self) -> Result<bool, String> {
        let str_e = from_u32(self.magic_str_e as u32).ok_or(format!("Error in from_u32(self.magic_str_e as u32)"))?;
        let str_l = from_u32(self.magic_str_l as u32).ok_or(format!("Error in from_u32(self.magic_str_l as u32)"))?;
        let str_f = from_u32(self.magic_str_f as u32).ok_or(format!("Error in from_u32(self.magic_str_f as u32)"))?;
        // println!("{:?}{:?}{:?}", str_e, str_l, str_f);
        Ok(str_e == 'E' && str_l == 'L' && str_f == 'F')
    }
}

#[repr(C)]
#[derive(Debug)]
struct ElfEhdr {
    e_ident: EIdent, // 15
    e_type: u16, // 17
    e_machine: u16, // 19
    e_version: u32, // 23
    e_entry: u64, // 31
    e_phoff: u64, // 39
    e_shoff: u64, // 47
    e_flags: u32, // 51
    e_ehsize: u16, // 53
    e_phentsize: u16, // 55
    e_phnum: u16, // 57
    e_shentsize: u16, // 59
    e_shnum: u16, // 61
    e_shstrndx: u16, // 63
}

// impl ElfEhdr {
//     pub fn
// }

#[derive(Debug)]
struct ElfEPhdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u32,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl ElfEPhdr {
    pub fn parse_unit(file: &Vec<u8>, elf_ehdr: &ElfEhdr, idx: usize) -> Self {
        let mut array: [u8; size_of::<ElfEPhdr>()] = [0x0; size_of::<ElfEPhdr>()];
        let start: usize = elf_ehdr.e_phoff as usize + size_of::<ElfEPhdr>() * idx;
        for idx_in_file in start..(start + size_of::<ElfEPhdr>()) {
            array[(idx_in_file - start) as usize] = file[idx_in_file as usize].clone();
        }
        unsafe { transmute::<[u8; size_of::<ElfEPhdr>()], ElfEPhdr>(array) }
    }
}

#[repr(C)]
#[derive(Debug)]
struct ElfEShdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

impl ElfEShdr {
    pub fn parse_unit(file: &Vec<u8>, elf_ehdr: &ElfEhdr, idx: usize) -> Self {
        let mut array: [u8; size_of::<ElfEShdr>()] = [0x0; size_of::<ElfEShdr>()];
        let start: usize = elf_ehdr.e_shoff as usize + size_of::<ElfEShdr>() * idx;
        for idx_in_file in start..(start + size_of::<ElfEShdr>()) {
            array[(idx_in_file - start) as usize] = file[idx_in_file as usize].clone();
        }
        unsafe { transmute::<[u8; size_of::<ElfEShdr>()], ElfEShdr>(array) }
    }

    pub fn get_type(&self) -> SHType {
        unsafe { transmute(self.sh_type) }
    }
}

#[repr(u32)]
#[derive(Debug)]
enum SHType {
    SHT_NULL = 0, SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4, SHT_HASH = 5, SHT_DYNAMIC = 6, SHT_NOTE = 7, SHT_NOBITS = 8, SHT_REL = 9, SHT_SHLIB = 10,
    SHT_DYNSYM = 11, SHT_SUNW_move = 0x6ffffffa, SHT_SUNW_COMDAT = 0x6ffffffb, SHT_SUNW_syminfo = 0x6ffffffc, SHT_SUNW_verdef = 0x6ffffffd, SHT_SUNW_verneed = 0x6ffffffe,
    SHT_SUNW_versym = 0x6fffffff, SHT_LOPROC = 0x70000000, SHT_HIPROC = 0x7fffffff, SHT_LOUSER = 0x80000000, SHT_HIUSER = 0xffffffff,
}

#[repr(C)]
#[derive(Debug)]
struct ElfESym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

impl ElfESym {
    pub fn parse(file: &Vec<u8>, elf_eshdr: &ElfEShdr, idx: usize) -> Self {
        let mut array: [u8; size_of::<ElfESym>()] = [0x0; size_of::<ElfESym>()];
        let start = elf_eshdr.sh_offset as usize + size_of::<ElfESym>() * idx;
        for idx in start..(start + size_of::<ElfESym>()) {
            array[idx - start] = file[idx].clone();
        }
        unsafe { transmute(array) }
    }
}

fn lookup_sym_name(file: &Vec<u8>, elf_eshdr_list: &Vec<ElfEShdr>, sym_name: &str) -> Result<Option<Vec<SymMap>>, String> {
    let mut result: Vec<SymMap> = vec![];
    for elf_eshdr in elf_eshdr_list.iter() {
        match elf_eshdr.get_type() {
            SHType::SHT_SYMTAB => {},
            _ => continue,
        };
        // println!("elf_eshdr: {:?}", elf_eshdr);
        let strtab_start_idx: usize = elf_eshdr_list[elf_eshdr.sh_link as usize].sh_offset as usize;
        // println!("strtab_start_idx: {:?}", strtab_start_idx);
        // println!("symtab_list size: {:?}", elf_eshdr.sh_size as usize / size_of::<ElfESym>());
        for idx in 0..elf_eshdr.sh_size as usize / size_of::<ElfESym>() {
            let symtab: ElfESym = ElfESym::parse(file, elf_eshdr, idx);
            // println!("idx: {:?}, {:?}, symtab: {:?}", idx, file[strtab_start_idx + symtab.st_name as usize], symtab);
            let mut jdx: usize = 0;
            let mut fn_name: String = "".to_owned();
            loop {
                // print!("{:?}", from_u32(file[strtab_start_idx + symtab.st_name as usize + jdx] as u32).unwrap());
                if from_u32(file[strtab_start_idx + symtab.st_name as usize + jdx] as u32) == Some('\u{0}') { break; }
                fn_name += &from_u32(file[strtab_start_idx + symtab.st_name as usize + jdx] as u32)
                    .ok_or("Error in from_u32(file[strtab_start_idx + symtab.st_name as usize + jdx] as u32)")?
                    .to_string();
                jdx += 1;
            }
            let demangled = try_demangle(&fn_name);
            let fn_origin_name = if let Ok(demangled_fn_name) = demangled { demangled_fn_name.to_string() } else { fn_name };
            // println!("{:?}", fn_origin_name);
            // if fn_origin_name.contains(sym_name) { return Ok(Some(symtab.st_value)) }
            if fn_origin_name.contains(sym_name) {
                result.push(SymMap {
                    fn_name: fn_origin_name,
                    vir_addr: symtab.st_value,
                })
            }
        }
    }
    return Ok(Some(result));
}

fn get_all_sym_name_vir_addr_map(file: &Vec<u8>, elf_eshdr_list: &Vec<ElfEShdr>) -> Result<Vec<SymMap>, String> {
    let mut result: Vec<SymMap> = vec![];
    for elf_eshdr in elf_eshdr_list.iter() {
        // println!("elf_eshdr.get_type(): {:?}", elf_eshdr.get_type());
        match elf_eshdr.get_type() {
            SHType::SHT_SYMTAB => {},
            _ => continue,
        };
        let strtab_start_idx: usize = elf_eshdr_list[elf_eshdr.sh_link as usize].sh_offset as usize;
        for idx in 0..elf_eshdr.sh_size as usize / size_of::<ElfESym>() {
            let symtab: ElfESym = ElfESym::parse(file, elf_eshdr, idx);
            let mut jdx: usize = 0;
            let mut fn_name: String = "".to_owned();
            loop {
                if from_u32(file[strtab_start_idx + symtab.st_name as usize + jdx] as u32) == Some('\u{0}') { break; }
                fn_name += &from_u32(file[strtab_start_idx + symtab.st_name as usize + jdx] as u32)
                    .ok_or("Error in from_u32(file[strtab_start_idx + symtab.st_name as usize + jdx] as u32)")?
                    .to_string();
                jdx += 1;
            }
            let demangled = try_demangle(&fn_name);
            let fn_origin_name = if let Ok(demangled_fn_name) = demangled { demangled_fn_name.to_string() } else { fn_name };
            result.push(SymMap {
                fn_name: fn_origin_name,
                vir_addr: symtab.st_value,
            });
        }
    }
    return Ok(result);
}

#[derive(Debug)]
pub struct SymMap {
    fn_name: String,
    vir_addr: u64,
}

impl SymMap {
    pub fn get_fn_name(&self) -> &String { &self.fn_name }
    pub fn get_vir_addr(&self) -> u64 { self.vir_addr }
}