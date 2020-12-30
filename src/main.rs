use nix::unistd::{Pid, getpid, sethostname, chroot, chdir, mkdir, pivot_root};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    println!("Hello, world!");
    println!("Hello, world PID: {:?}", getpid());
    let mut idx: usize = 0;
    loop {
        idx += 1;
        main2(idx);
        sleep(Duration::from_secs(2));
    }
}

fn main2(idx: usize) {
    println!("aaaaaaa: {:?}", idx);
}