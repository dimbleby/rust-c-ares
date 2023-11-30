extern crate c_ares;

fn main() {
    let (vstr, vint) = c_ares::version();
    println!("Version {:x} ({})", vint, vstr);

    #[cfg(cares1_23)]
    {
        let safety = c_ares::thread_safety();
        println!("Built with thread-safety? {}", safety);
    }
}
