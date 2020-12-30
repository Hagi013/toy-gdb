use anyhow::{Result, Error, Context};
use std::io::{Write, stdout};
use std::thread::sleep;
use nix::unistd::{Pid, getpid};
use nix::sys::wait::WaitStatus;
use nix::sys::signal;
use nix::libc::{self, user_regs_struct};
use std::time::Duration;
use std::collections::HashMap;
use std::fs::{read, read_to_string, read_dir};

mod ptrace;
mod check_fn_viradd;

fn main() -> Result<()> {
    let commands: Vec<String> = std::env::args().collect();
    if commands.len() < 2 {
        println!("You should input pid.");
        println!("ex) cargo run --bin check-state <pid> <function_filter>");
        std::process::exit(0);
    }
    let pid_str = &commands[1];
    let pid_num = pid_str.parse::<i64>().unwrap_or(-1);
    if pid_num == -1 { panic!("invalid pid."); }
    let pid = Pid::from_raw(pid_num as libc::pid_t);
    println!("pid: {:?}", pid);
    let filter: Option<&str> = if (&commands).len() > 2 { Some(&commands[2]) } else { None };

    let pid_binary_path_option = get_pid_binary_path(&pid.to_string());
    let pid_binary_path = if pid_binary_path_option.is_some() { pid_binary_path_option.unwrap() } else { panic!("there is no file proc/{}/exe", pid_str); };
    let sym_map_list: Vec<check_fn_viradd::SymMap> = check_fn_viradd::get_fn_vir_address_maps(&pid_binary_path);
    // println!("sym_map_list: {:?}", sym_map_list);

    let debug_point = decide_debug_point(&pid, filter, &sym_map_list).with_context(|| "Error in decide_debug_point")?;

    ptrace::attach(pid).unwrap();

    loop {
        let status: WaitStatus = ptrace::wait_pid(pid).unwrap();
        let pid = status.pid().unwrap();
        println!("status: {:?}", status);
        let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
        print_regs(&pid, &regs);

        let instruction_res = ptrace::peek_text(pid, debug_point);
        println!("instruction_res: {:?}", instruction_res);
        let instruction = if instruction_res.is_ok() { instruction_res.unwrap() } else { panic!(format!("ptrace::peek_text error.[instruction_res: {:?}, pid: {:?}, debug_point: {:x}]", instruction_res, pid, debug_point)) };

        ptrace::poke_text(pid, debug_point, (instruction & !0xff | 0xcc) as u64);

        ptrace::cont(pid)?;

        let status: WaitStatus = ptrace::wait_pid(pid).unwrap();
        println!("status: {:?}" , status);
        let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
        print_regs(&pid, &regs);

        // wait
        wait_until_enter();

        regs.rip = debug_point;
        ptrace::setregs(pid, regs);
        ptrace::poke_text(pid, debug_point, instruction as u64);
        ptrace::syscall_step(pid);
    }
    Ok(())
}

fn decide_debug_point(pid: &Pid, filter: Option<&str>, sym_map_list: &Vec<check_fn_viradd::SymMap>) -> Result<u64> {
    let filtered_sym_map = show_filtered_map(&filter, sym_map_list);

    println!("");
    println!("");
    println!("Input debug function symbol name");

    let gaven_fn_name = {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();
        s.trim_end().to_owned()
    };

    println!("in: {}", gaven_fn_name);
    let target_sym_map: Vec<&check_fn_viradd::SymMap> = filtered_sym_map.iter().cloned().filter(|sym_map| sym_map.get_fn_name() == &gaven_fn_name).collect();
    println!("filtered_sym_map: {:?}", filtered_sym_map);

    let fn_address: u64 = if target_sym_map.len() == 1 { target_sym_map[0].get_vir_addr() } else { panic!("You should specify debug point function name.") };
    let base_text_vir_addr = fetch_text_base_vir_address(&pid.to_string()).with_context(|| "Error in fetch_text_base_vir_address")?;
    Ok(fn_address + base_text_vir_addr)
}

fn show_filtered_map<'a>(filter: &Option<&str>, sym_map_list: &'a Vec<check_fn_viradd::SymMap>) -> Vec<&'a check_fn_viradd::SymMap> {
    let mut filtered_sym_map: Vec<&check_fn_viradd::SymMap> = vec![];
    // symbolを一覧表示させ、どこで確認したいかUserに入力させる
    for sym_map in sym_map_list.iter() {
        let fn_name = sym_map.get_fn_name();
        if filter.is_none() || fn_name.contains(filter.unwrap()) {
            println!("fn_name: {}", fn_name);
            filtered_sym_map.push(sym_map);
        }
    }
    filtered_sym_map
}

fn get_pid_binary_path(pid: &str) -> Option<String> {
    let binary_path = format!("/proc/{}/exe", pid);
    let res = read(&binary_path);
    let res_dir = read_dir(&binary_path);
    if res.is_ok() && res_dir.is_err() {
        return Some(binary_path);
    }
    None
}

fn print_regs(pid: &Pid, regs: &user_regs_struct) {
    println!("pid: {:?}, orig_rax: {:?}, rsi: 0x{:x}, rdx: 0x{:x}, rdi: 0x{:x}, rax: {:?}, rip: 0x{:x}, rbx: 0x{:x}", pid, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax, regs.rip, regs.rbx);
    println!("pid: {:?}, rsp: 0x{:x}, cs: 0x{:x}, ds: 0x{:x}, ss: 0x{:x}, rbp: 0x{:x}", pid, regs.rsp, regs.cs, regs.ds, regs.ss, regs.rbp);
}

fn fetch_text_base_vir_address(pid: &str) -> Result<u64> {
    let path = format!("/proc/{}/maps", pid);
    let res = read_to_string(&path).with_context(|| "Error happens in fetch_text_base_vir_address method.")?;
    let first_line = res.split('\n').find(|e| { true }).with_context(|| "first_line is none in fetch_text_base_vir_address method.")?;
    let memory_map = first_line.split(' ').find(|e| { true }).with_context(|| "memory_map is none in fetch_text_base_vir_address method.")?;
    let text_start_at = memory_map.split('-').find(|e| { true }).with_context(|| "text_start_at is none in fetch_text_base_vir_address method.")?;
    println!("text_start_at: {:?}", text_start_at);
    u64::from_str_radix(text_start_at, 16).with_context(|| "u64::from_str_radix error in fetch_text_base_vir_address method.")
}


fn wait_until_enter() {
    println!("Wait!!");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
}