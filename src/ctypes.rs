#![allow(non_camel_case_types)]
#[cfg(unix)]
mod unix {
  extern crate libc;

  pub type fd_set = libc::fd_set;

  #[repr(C)]
  #[derive(Debug)]
  #[allow(raw_pointer_derive)]
  pub struct hostent {
      pub h_name: *mut libc::c_char,
      pub h_aliases: *mut *mut libc::c_char,
      pub h_addrtype: libc::c_int,
      pub h_length: libc::c_int,
      pub h_addr_list: *mut *mut libc::c_char,
  }

  pub type in_addr = libc::in_addr;
  pub type in6_addr = libc::in6_addr;
  pub type sa_family_t = libc::sa_family_t;
  pub type sockaddr = libc::sockaddr;
  pub type sockaddr_in = libc::sockaddr_in;
  pub type sockaddr_in6 = libc::sockaddr_in6;

  pub const AF_INET: i32 = libc::AF_INET;
  pub const AF_INET6: i32 = libc::AF_INET6;
}

#[cfg(windows)]
mod windows {
  extern crate winapi;

  pub type fd_set = winapi::fd_set;
  pub type hostent = winapi::winsock2::hostent;
  pub type in_addr = winapi::in_addr;
  pub type in6_addr = winapi::in6_addr;
  pub type sa_family_t = winapi::ws2def::ADDRESS_FAMILY;
  pub type sockaddr = winapi::SOCKADDR;
  pub type sockaddr_in = winapi::ws2def::SOCKADDR_IN;
  pub type sockaddr_in6 = winapi::ws2ipdef::sockaddr_in6;

  pub const AF_INET: i32 = winapi::ws2def::AF_INET;
  pub const AF_INET6: i32 = winapi::ws2def::AF_INET6;
}

#[cfg(unix)]
pub use self::unix::*;

#[cfg(windows)]
pub use self::windows::*;
