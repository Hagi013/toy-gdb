use anyhow::Result;
use nix::sys::{ptrace, signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use nix::libc::{self, user_regs_struct};
use nix::errno::Errno;

pub fn attach(pid: Pid) -> Result<()> {
    ptrace::attach(pid)?;
    Ok(())
}

pub fn traceme() -> Result<()> {
    ptrace::traceme()?;
    Ok(())
}

pub fn detach(pid: Pid) -> Result<()> {
    ptrace::detach(pid, None)?;
    Ok(())
}

pub fn cont(pid: Pid) -> Result<()> {
    ptrace::cont(pid, None)?;
    Ok(())
}

pub fn set_tracesysgood(pid: Pid) -> Result<()>  {
    let status = wait_pid(pid)?;
    match status {
        WaitStatus::Stopped(pid, signal::SIGSTOP) => {
            // ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD).unwrap();
            set_option_simple(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD).unwrap();
        },
        _ => {
            panic!("Not Stopped Process...{:?}", pid);
        }
    }
    syscall(pid);
    Ok(())
}

pub fn set_emulate_option(pid: Pid) -> Result<()> {
    let status = wait_pid(pid)?;
    match status {
        WaitStatus::Stopped(pid, signal::SIGSTOP) => {
            // ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEFORK | ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_TRACECLONE).unwrap();
            set_option_simple(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEFORK | ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_TRACECLONE | ptrace::Options::PTRACE_O_TRACEEXIT).unwrap();
        },
        _ => {
            panic!("Not Stopped Process...{:?}, Status: {:?}", pid, status);
        }
    }
    syscall(pid);
    Ok(())
}

pub fn set_emulate_option_simple(pid: Pid) -> Result<()> {
    set_option_simple(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEFORK | ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_TRACECLONE).unwrap();
    Ok(())
}

pub fn set_option_simple(pid: Pid, options: ptrace::Options) -> Result<()> {
    ptrace::setoptions(pid, options).unwrap();
    Ok(())
}

pub fn wait_pid(pid: Pid) -> Result<WaitStatus> {
    let status = waitpid(pid, None)?;
    Ok(status)
}

pub fn wait_all() -> Result<WaitStatus> {
    // let status = waitpid(Pid::from_raw(-1), Some)?;
    let status = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL))?;
    Ok(status)
}

pub fn syscall(pid: Pid) {
    ptrace::syscall(pid, None);
}

pub fn syscall_step(pid: Pid) {
    ptrace::step(pid, None);
}

pub fn getregs(pid: Pid) -> Result<user_regs_struct> {
    Ok(ptrace::getregs(pid)?)
}

pub fn setregs(pid: Pid, urs: user_regs_struct) -> Result<()> {
    Ok(ptrace::setregs(pid, urs)?)
}

pub fn read_memory(pid: Pid, addr: u64) -> Result<i64> {
    let res = ptrace::read(pid, addr as *mut std::ffi::c_void)?;
    Ok(res as i64)
}

// pub fn write_data(pid: Pid, addr: u64, data: u64) -> Result<()> {
//     ptrace::write(pid, addr as *mut std::ffi::c_void, data as *mut libc::c_void).unwrap();
//     Ok(())
// }
pub fn write_data(pid: Pid, addr: u64, data: u64) -> Result<()> {
    unsafe {
        ptrace::write(pid, addr as *mut std::ffi::c_void, data as *mut libc::c_void).unwrap();
    }
    Ok(())
}

pub fn sysemu(pid: Pid) -> Result<()> {
    Errno::result(
        unsafe { libc::ptrace(31 as libc::c_uint, libc::pid_t::from(pid), std::ptr::null_mut::<libc::c_uint>(), std::ptr::null_mut::<libc::c_uint>()) }
        // unsafe { libc::ptrace(24 as libc::c_uint, libc::pid_t::from(pid) as i32, std::ptr::null_mut::<std::ffi::c_void>(), std::ptr::null_mut::<std::ffi::c_void>()) }
    )
        .map(drop);
    Ok(())
}

pub fn sysemu_single(pid: Pid) -> Result<()> {
    Errno::result(
        unsafe { libc::ptrace(32 as libc::c_uint, libc::pid_t::from(pid), std::ptr::null_mut::<libc::c_uint>(), std::ptr::null_mut::<libc::c_uint>()) }
    )
        .map(drop);
    Ok(())

}

pub fn peek_text(pid: Pid, vir_addr: u64) -> Result<i64> {
    // ref) https://rust-lang.github.io/regex/src/libc/unix/notbsd/linux/other/mod.rs.html#579
    let res = Errno::result(
        unsafe { libc::ptrace(1 as libc::c_uint, libc::pid_t::from(pid), vir_addr as *mut libc::c_int, 0 as *mut libc::c_void) }
    )?;
    Ok(res as i64)
    // let res: i64 = unsafe { ptrace::ptrace(nix::sys::ptrace::Request::PTRACE_PEEKTEXT, pid, vir_addr as *mut libc::c_void, 0 as *mut libc::c_void)? };
    // Ok(res)
}

pub fn poke_text(pid: Pid, vir_addr: u64, data: u64) -> Result<i64> {
    // ref) https://rust-lang.github.io/regex/src/libc/unix/notbsd/linux/other/mod.rs.html#579
    let res = Errno::result(
        unsafe { libc::ptrace(4 as libc::c_uint, libc::pid_t::from(pid), vir_addr as *mut libc::c_char, data as *mut libc::c_void) }
    )?;
    Ok(res as i64)
}

pub fn poke_user(pid: Pid, addr: u64, data: u64) -> Result<()> {
    Errno::result(
        unsafe { libc::ptrace(6 as libc::c_uint, libc::pid_t::from(pid), addr as *mut libc::c_void, data as *mut libc::c_void) }
    )
        .map(drop);
    Ok(())
}

pub fn get_event(pid: Pid) -> Result<i64> {
    let u_long: i64 = ptrace::getevent(pid)?;
    Ok(u_long)
}

pub fn get_siginfo(pid: Pid) -> Result<libc::siginfo_t> {
    let siginfo = ptrace::getsiginfo(pid)?;
    Ok(siginfo)
}
