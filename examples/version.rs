extern crate c_ares;

fn main() {
    let (vstr, vint) = c_ares::version();
    println!("Version {:x} ({})", vint, vstr);
}
