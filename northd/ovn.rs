/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use ::nom::*;
use ::differential_datalog::record;
use ::std::ffi;
use ::std::ptr;
use ::std::default;
use ::std::process;
use ::std::os::raw;
use ::libc;

pub fn warn(msg: &String) {
    warn_(msg.as_str())
}

pub fn warn_(msg: &str) {
    unsafe {
        ddlog_warn(ffi::CString::new(msg).unwrap().as_ptr());
    }
}

pub fn err_(msg: &str) {
    unsafe {
        ddlog_err(ffi::CString::new(msg).unwrap().as_ptr());
    }
}

pub fn abort(msg: &String) {
    abort_(msg.as_str())
}

fn abort_(msg: &str) {
    err_(format!("DDlog error: {}.", msg).as_ref());
    process::abort();
}

const ETH_ADDR_SIZE:    usize = 6;
const IN6_ADDR_SIZE:    usize = 16;
const INET6_ADDRSTRLEN: usize = 46;
const INET_ADDRSTRLEN:  usize = 16;
const ETH_ADDR_STRLEN:  usize = 17;

const AF_INET: usize = 2;
const AF_INET6: usize = 10;

/* Implementation for externs declared in ovn.dl */

#[repr(C)]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Serialize, Deserialize, Debug, IntoRecord, Mutator)]
pub struct eth_addr_c {
    x: [u8; ETH_ADDR_SIZE]
}

impl eth_addr_c {
    pub fn from_ddlog(d: &eth_addr) -> Self {
        eth_addr_c {
            x: [(d.ha >> 40) as u8,
                (d.ha >> 32) as u8,
                (d.ha >> 24) as u8,
                (d.ha >> 16) as u8,
                (d.ha >> 8) as u8,
                d.ha as u8]
        }
    }
    pub fn to_ddlog(&self) -> eth_addr {
        let ea0 = u16::from_be_bytes([self.x[0], self.x[1]]) as u64;
        let ea1 = u16::from_be_bytes([self.x[2], self.x[3]]) as u64;
        let ea2 = u16::from_be_bytes([self.x[4], self.x[5]]) as u64;
        eth_addr { ha: (ea0 << 32) | (ea1 << 16) | ea2 }
    }
}

pub fn eth_addr2string(addr: &eth_addr) -> String {
    let c = eth_addr_c::from_ddlog(addr);
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            c.x[0], c.x[1], c.x[2], c.x[3], c.x[4], c.x[5])
}

pub fn eth_addr_from_string(s: &String) -> ddlog_std::Option<eth_addr> {
    let mut ea: eth_addr_c = Default::default();
    unsafe {
        if ovs::eth_addr_from_string(string2cstr(s).as_ptr(), &mut ea as *mut eth_addr_c) {
            ddlog_std::Option::Some{x: ea.to_ddlog()}
        } else {
            ddlog_std::Option::None
        }
    }
}

#[repr(C)]
struct in6_addr_c {
    bytes: [u8; 16]
}

impl Default for in6_addr_c {
    fn default() -> Self {
        in6_addr_c {
            bytes: [0; 16]
        }
    }
}

impl in6_addr_c {
    pub fn from_ddlog(d: &in6_addr) -> Self {
        in6_addr_c{bytes: d.aaaa.to_be_bytes()}
    }
    pub fn to_ddlog(&self) -> in6_addr {
        in6_addr{aaaa: u128::from_be_bytes(self.bytes)}
    }
}

pub fn string_mapped(addr: &in6_addr) -> String {
    let addr = in6_addr_c::from_ddlog(addr);
    let mut addr_str = [0 as i8; INET6_ADDRSTRLEN];
    unsafe {
        ovs::ipv6_string_mapped(&mut addr_str[0] as *mut raw::c_char, &addr as *const in6_addr_c);
        cstr2string(&addr_str as *const raw::c_char)
    }
}

pub fn json_string_escape(s: &String) -> String {
    let mut ds = ovs_ds::new();
    unsafe {
        ovs::json_string_escape(ffi::CString::new(s.as_str()).unwrap().as_ptr() as *const raw::c_char,
                                &mut ds as *mut ovs_ds);
    };
    unsafe{ds.into_string()}
}

pub fn extract_lsp_addresses(address: &String) -> ddlog_std::Option<lport_addresses> {
    unsafe {
        let mut laddrs: lport_addresses_c = Default::default();
        if ovn_c::extract_lsp_addresses(string2cstr(address).as_ptr(),
                                      &mut laddrs as *mut lport_addresses_c) {
            ddlog_std::Option::Some{x: laddrs.into_ddlog()}
        } else {
            ddlog_std::Option::None
        }
    }
}

pub fn extract_addresses(address: &String) -> ddlog_std::Option<lport_addresses> {
    unsafe {
        let mut laddrs: lport_addresses_c = Default::default();
        let mut ofs: raw::c_int = 0;
        if ovn_c::extract_addresses(string2cstr(address).as_ptr(),
                                  &mut laddrs as *mut lport_addresses_c,
                                  &mut ofs as *mut raw::c_int) {
            ddlog_std::Option::Some{x: laddrs.into_ddlog()}
        } else {
            ddlog_std::Option::None
        }
    }
}

pub fn extract_lrp_networks(mac: &String, networks: &ddlog_std::Set<String>) -> ddlog_std::Option<lport_addresses>
{
    unsafe {
        let mut laddrs: lport_addresses_c = Default::default();
        let mut networks_cstrs = Vec::with_capacity(networks.x.len());
        let mut networks_ptrs = Vec::with_capacity(networks.x.len());
        for net in networks.x.iter() {
            networks_cstrs.push(string2cstr(net));
            networks_ptrs.push(networks_cstrs.last().unwrap().as_ptr());
        };
        if ovn_c::extract_lrp_networks__(string2cstr(mac).as_ptr(), networks_ptrs.as_ptr() as *const *const raw::c_char,
                                       networks_ptrs.len(), &mut laddrs as *mut lport_addresses_c) {
            ddlog_std::Option::Some{x: laddrs.into_ddlog()}
        } else {
            ddlog_std::Option::None
        }
    }
}

pub fn ovn_internal_version() -> String {
    unsafe {
        let s = ovn_c::ovn_get_internal_version();
        let retval = cstr2string(s);
        free(s as *mut raw::c_void);
        retval
    }
}

pub fn ipv6_parse_masked(s: &String) -> ddlog_std::Either<String, ddlog_std::tuple2<in6_addr, in6_addr>>
{
    unsafe {
        let mut ip: in6_addr_c = Default::default();
        let mut mask: in6_addr_c = Default::default();
        let err = ovs::ipv6_parse_masked(string2cstr(s).as_ptr(), &mut ip as *mut in6_addr_c, &mut mask as *mut in6_addr_c);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            ddlog_std::Either::Left{l: errstr}
        } else {
            ddlog_std::Either::Right{r: ddlog_std::tuple2(ip.to_ddlog(), mask.to_ddlog())}
        }
    }
}

pub fn ipv6_parse_cidr(s: &String) -> ddlog_std::Either<String, ddlog_std::tuple2<in6_addr, u32>>
{
    unsafe {
        let mut ip: in6_addr_c = Default::default();
        let mut plen: raw::c_uint = 0;
        let err = ovs::ipv6_parse_cidr(string2cstr(s).as_ptr(), &mut ip as *mut in6_addr_c, &mut plen as *mut raw::c_uint);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            ddlog_std::Either::Left{l: errstr}
        } else {
            ddlog_std::Either::Right{r: ddlog_std::tuple2(ip.to_ddlog(), plen as u32)}
        }
    }
}

pub fn ipv6_parse(s: &String) -> ddlog_std::Option<in6_addr>
{
    unsafe {
        let mut ip: in6_addr_c = Default::default();
        let res = ovs::ipv6_parse(string2cstr(s).as_ptr(), &mut ip as *mut in6_addr_c);
        if (res) {
            ddlog_std::Option::Some{x: ip.to_ddlog()}
        } else {
            ddlog_std::Option::None
        }
    }
}

pub type ovs_be32 = u32;

impl in_addr {
    pub fn from_be32(nl: ovs_be32) -> in_addr {
        in_addr{a: ddlog_std::ntohl(&nl)}
    }
    pub fn to_be32(&self) -> ovs_be32 {
        ddlog_std::htonl(&self.a)
    }
}

pub fn ip_parse_masked(s: &String) -> ddlog_std::Either<String, ddlog_std::tuple2<in_addr, in_addr>>
{
    unsafe {
        let mut ip: ovs_be32 = 0;
        let mut mask: ovs_be32 = 0;
        let err = ovs::ip_parse_masked(string2cstr(s).as_ptr(), &mut ip as *mut ovs_be32, &mut mask as *mut ovs_be32);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            ddlog_std::Either::Left{l: errstr}
        } else {
            ddlog_std::Either::Right{r: ddlog_std::tuple2(in_addr::from_be32(ip),
                                                          in_addr::from_be32(mask))}
        }
    }
}

pub fn ip_parse_cidr(s: &String) -> ddlog_std::Either<String, ddlog_std::tuple2<in_addr, u32>>
{
    unsafe {
        let mut ip: ovs_be32 = 0;
        let mut plen: raw::c_uint = 0;
        let err = ovs::ip_parse_cidr(string2cstr(s).as_ptr(), &mut ip as *mut ovs_be32, &mut plen as *mut raw::c_uint);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            ddlog_std::Either::Left{l: errstr}
        } else {
            ddlog_std::Either::Right{r: ddlog_std::tuple2(in_addr::from_be32(ip), plen as u32)}
        }
    }
}

pub fn ip_parse(s: &String) -> ddlog_std::Option<in_addr>
{
    unsafe {
        let mut ip: ovs_be32 = 0;
        if (ovs::ip_parse(string2cstr(s).as_ptr(), &mut ip as *mut ovs_be32)) {
            ddlog_std::Option::Some{x: in_addr::from_be32(ip)}
        } else {
            ddlog_std::Option::None
        }
    }
}

pub fn is_dynamic_lsp_address(address: &String) -> bool {
    unsafe {
        ovn_c::is_dynamic_lsp_address(string2cstr(address).as_ptr())
    }
}

pub fn split_addresses(addresses: &String) -> ddlog_std::tuple2<ddlog_std::Set<String>, ddlog_std::Set<String>> {
    let mut ip4_addrs = ovs_svec::new();
    let mut ip6_addrs = ovs_svec::new();
    unsafe {
        ovn_c::split_addresses(string2cstr(addresses).as_ptr(), &mut ip4_addrs as *mut ovs_svec, &mut ip6_addrs as *mut ovs_svec);
        ddlog_std::tuple2(ip4_addrs.into_strings(), ip6_addrs.into_strings())
    }
}

pub fn scan_eth_addr(s: &String) -> ddlog_std::Option<eth_addr> {
    let mut ea: eth_addr_c = Default::default();
    unsafe {
        if ovs::ovs_scan(string2cstr(s).as_ptr(), b"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\0".as_ptr() as *const raw::c_char,
                         &mut ea.x[0] as *mut u8, &mut ea.x[1] as *mut u8,
                         &mut ea.x[2] as *mut u8, &mut ea.x[3] as *mut u8,
                         &mut ea.x[4] as *mut u8, &mut ea.x[5] as *mut u8)
        {
            ddlog_std::Option::Some{x: ea.to_ddlog()}
        } else {
            ddlog_std::Option::None
        }
    }
}

pub fn scan_eth_addr_prefix(s: &String) -> ddlog_std::Option<eth_addr> {
    let mut b2: u8 = 0;
    let mut b1: u8 = 0;
    let mut b0: u8 = 0;
    unsafe {
        if ovs::ovs_scan(string2cstr(s).as_ptr(), b"%hhx:%hhx:%hhx\0".as_ptr() as *const raw::c_char,
                         &mut b2 as *mut u8, &mut b1 as *mut u8, &mut b0 as *mut u8)
        {
            ddlog_std::Option::Some{x: eth_addr{ha: ((b2 as u64) << 40) | ((b1 as u64) << 32) | ((b0 as u64) << 24)} }
        } else {
            ddlog_std::Option::None
        }
    }
}

pub fn scan_static_dynamic_ip(s: &String) -> ddlog_std::Option<in_addr> {
    let mut ip0: u8 = 0;
    let mut ip1: u8 = 0;
    let mut ip2: u8 = 0;
    let mut ip3: u8 = 0;
    let mut n: raw::c_uint = 0;
    unsafe {
        if ovs::ovs_scan(string2cstr(s).as_ptr(), b"dynamic %hhu.%hhu.%hhu.%hhu%n\0".as_ptr() as *const raw::c_char,
                         &mut ip0 as *mut u8,
                         &mut ip1 as *mut u8,
                         &mut ip2 as *mut u8,
                         &mut ip3 as *mut u8,
                         &mut n) && s.len() == (n as usize)
        {
            let a0 = (ip0 as u32) << 24;
            let a1 = (ip1 as u32) << 16;
            let a2 = (ip2 as u32) << 8;
            let a3 = ip3 as u32;
            ddlog_std::Option::Some{x: in_addr{a: a0 | a1 | a2 | a3}}
        } else {
            ddlog_std::Option::None
        }
    }
}

pub fn ip_address_and_port_from_lb_key(k: &String) ->
    ddlog_std::Option<ddlog_std::tuple2<v46_ip, u16>>
{
    unsafe {
        let mut ip_address: *mut raw::c_char = ptr::null_mut();
        let mut port: libc::uint16_t = 0;
        let mut addr_family: raw::c_int = 0;

        ovn_c::ip_address_and_port_from_lb_key(string2cstr(k).as_ptr(), &mut ip_address as *mut *mut raw::c_char,
                                             &mut port as *mut libc::uint16_t, &mut addr_family as *mut raw::c_int);
        if (ip_address != ptr::null_mut()) {
            match (ip46_parse(&cstr2string(ip_address))) {
                ddlog_std::Option::Some{x: ip46} => {
                    let res = ddlog_std::tuple2(ip46, port as u16);
                    free(ip_address as *mut raw::c_void);
                    return ddlog_std::Option::Some{x: res}
                },
                _ => ()
            }
        }
        ddlog_std::Option::None
    }
}

pub fn str_to_int(s: &String, base: &u16) -> ddlog_std::Option<u64> {
    let mut i: raw::c_int = 0;
    let ok = unsafe {
        ovs::str_to_int(string2cstr(s).as_ptr(), *base as raw::c_int, &mut i as *mut raw::c_int)
    };
    if ok {
        ddlog_std::Option::Some{x: i as u64}
    } else {
        ddlog_std::Option::None
    }
}

pub fn str_to_uint(s: &String, base: &u16) -> ddlog_std::Option<u64> {
    let mut i: raw::c_uint = 0;
    let ok = unsafe {
        ovs::str_to_uint(string2cstr(s).as_ptr(), *base as raw::c_int, &mut i as *mut raw::c_uint)
    };
    if ok {
        ddlog_std::Option::Some{x: i as u64}
    } else {
        ddlog_std::Option::None
    }
}

pub fn inet6_ntop(addr: &in6_addr) -> String {
    let addr_c = in6_addr_c::from_ddlog(addr);
    let mut buf = [0 as i8; INET6_ADDRSTRLEN];
    unsafe {
        let res = inet_ntop(AF_INET6 as raw::c_int, &addr_c as *const in6_addr_c as *const raw::c_void,
                            &mut buf[0] as *mut raw::c_char, INET6_ADDRSTRLEN as libc::socklen_t);
        if res == ptr::null() {
            warn(&format!("inet_ntop({:?}) failed", *addr));
            "".to_owned()
        } else {
            cstr2string(&buf as *const raw::c_char)
        }
    }
}

/* Internals */

unsafe fn cstr2string(s: *const raw::c_char) -> String {
    ffi::CStr::from_ptr(s).to_owned().into_string().
        unwrap_or_else(|e|{ warn(&format!("cstr2string: {}", e)); "".to_owned() })
}

fn string2cstr(s: &String) -> ffi::CString {
    ffi::CString::new(s.as_str()).unwrap()
}

/* OVS dynamic string type */
#[repr(C)]
struct ovs_ds {
    s: *mut raw::c_char,       /* Null-terminated string. */
    length: libc::size_t,      /* Bytes used, not including null terminator. */
    allocated: libc::size_t    /* Bytes allocated, not including null terminator. */
}

impl ovs_ds {
    pub fn new() -> ovs_ds {
        ovs_ds{s: ptr::null_mut(), length: 0, allocated: 0}
    }

    pub unsafe fn into_string(mut self) -> String {
        let res = cstr2string(ovs::ds_cstr(&self as *const ovs_ds));
        ovs::ds_destroy(&mut self as *mut ovs_ds);
        res
    }
}

/* OVS string vector type */
#[repr(C)]
struct ovs_svec {
    names: *mut *mut raw::c_char,
    n: libc::size_t,
    allocated: libc::size_t
}

impl ovs_svec {
    pub fn new() -> ovs_svec {
        ovs_svec{names: ptr::null_mut(), n: 0, allocated: 0}
    }

    pub unsafe fn into_strings(mut self) -> ddlog_std::Set<String> {
        let mut res: ddlog_std::Set<String> = ddlog_std::Set::new();
        unsafe {
            for i in 0..self.n {
                res.insert(cstr2string(*self.names.offset(i as isize)));
            }
            ovs::svec_destroy(&mut self as *mut ovs_svec);
        }
        res
    }
}


// ovn/lib/ovn-util.h
#[repr(C)]
struct ipv4_netaddr_c {
    addr:       libc::uint32_t,
    mask:       libc::uint32_t,
    network:    libc::uint32_t,
    plen:       raw::c_uint,

    addr_s:     [raw::c_char; INET_ADDRSTRLEN + 1],  /* "192.168.10.123" */
    network_s:  [raw::c_char; INET_ADDRSTRLEN + 1],  /* "192.168.10.0" */
    bcast_s:    [raw::c_char; INET_ADDRSTRLEN + 1]   /* "192.168.10.255" */
}

impl Default for ipv4_netaddr_c {
    fn default() -> Self {
        ipv4_netaddr_c {
            addr:       0,
            mask:       0,
            network:    0,
            plen:       0,
            addr_s:     [0; INET_ADDRSTRLEN + 1],
            network_s:  [0; INET_ADDRSTRLEN + 1],
            bcast_s:    [0; INET_ADDRSTRLEN + 1]
        }
    }
}

impl ipv4_netaddr_c {
    pub fn to_ddlog(&self) -> ipv4_netaddr {
        ipv4_netaddr{
            addr:       in_addr::from_be32(self.addr),
            plen:       self.plen,
        }
    }
}

#[repr(C)]
struct ipv6_netaddr_c {
    addr:       in6_addr_c,     /* fc00::1 */
    mask:       in6_addr_c,     /* ffff:ffff:ffff:ffff:: */
    sn_addr:    in6_addr_c,     /* ff02:1:ff00::1 */
    network:    in6_addr_c,     /* fc00:: */
    plen:       raw::c_uint,      /* CIDR Prefix: 64 */

    addr_s:     [raw::c_char; INET6_ADDRSTRLEN + 1],    /* "fc00::1" */
    sn_addr_s:  [raw::c_char; INET6_ADDRSTRLEN + 1],    /* "ff02:1:ff00::1" */
    network_s:  [raw::c_char; INET6_ADDRSTRLEN + 1]     /* "fc00::" */
}

impl Default for ipv6_netaddr_c {
    fn default() -> Self {
        ipv6_netaddr_c {
            addr:       Default::default(),
            mask:       Default::default(),
            sn_addr:    Default::default(),
            network:    Default::default(),
            plen:       0,
            addr_s:     [0; INET6_ADDRSTRLEN + 1],
            sn_addr_s:  [0; INET6_ADDRSTRLEN + 1],
            network_s:  [0; INET6_ADDRSTRLEN + 1]
        }
    }
}

impl ipv6_netaddr_c {
    pub unsafe fn to_ddlog(&self) -> ipv6_netaddr {
        ipv6_netaddr{
            addr:       in6_addr_c::to_ddlog(&self.addr),
            plen:       self.plen
        }
    }
}


// ovn-util.h
#[repr(C)]
struct lport_addresses_c {
    ea_s:           [raw::c_char; ETH_ADDR_STRLEN + 1],
    ea:             eth_addr_c,
    n_ipv4_addrs:   libc::size_t,
    ipv4_addrs:     *mut ipv4_netaddr_c,
    n_ipv6_addrs:   libc::size_t,
    ipv6_addrs:     *mut ipv6_netaddr_c
}

impl Default for lport_addresses_c {
    fn default() -> Self {
        lport_addresses_c {
            ea_s:           [0; ETH_ADDR_STRLEN + 1],
            ea:             Default::default(),
            n_ipv4_addrs:   0,
            ipv4_addrs:     ptr::null_mut(),
            n_ipv6_addrs:   0,
            ipv6_addrs:     ptr::null_mut()
        }
    }
}

impl lport_addresses_c {
    pub unsafe fn into_ddlog(mut self) -> lport_addresses {
        let mut ipv4_addrs = ddlog_std::Vec::with_capacity(self.n_ipv4_addrs);
        for i in 0..self.n_ipv4_addrs {
            ipv4_addrs.push((&*self.ipv4_addrs.offset(i as isize)).to_ddlog())
        }
        let mut ipv6_addrs = ddlog_std::Vec::with_capacity(self.n_ipv6_addrs);
        for i in 0..self.n_ipv6_addrs {
            ipv6_addrs.push((&*self.ipv6_addrs.offset(i as isize)).to_ddlog())
        }
        let res = lport_addresses {
            ea:         self.ea.to_ddlog(),
            ipv4_addrs: ipv4_addrs,
            ipv6_addrs: ipv6_addrs
        };
        ovn_c::destroy_lport_addresses(&mut self as *mut lport_addresses_c);
        res
    }
}

/* functions imported from ovn-northd.c */
extern "C" {
    fn ddlog_warn(msg: *const raw::c_char);
    fn ddlog_err(msg: *const raw::c_char);
}

/* functions imported from libovn */
mod ovn_c {
    use ::std::os::raw;
    use ::libc;
    use super::lport_addresses_c;
    use super::ovs_svec;
    use super::in6_addr_c;

    #[link(name = "ovn")]
    extern "C" {
        // ovn/lib/ovn-util.h
        pub fn extract_lsp_addresses(address: *const raw::c_char, laddrs: *mut lport_addresses_c) -> bool;
        pub fn extract_addresses(address: *const raw::c_char, laddrs: *mut lport_addresses_c, ofs: *mut raw::c_int) -> bool;
        pub fn extract_lrp_networks__(mac: *const raw::c_char, networks: *const *const raw::c_char,
                                      n_networks: libc::size_t, laddrs: *mut lport_addresses_c) -> bool;
        pub fn destroy_lport_addresses(addrs: *mut lport_addresses_c);
        pub fn is_dynamic_lsp_address(address: *const raw::c_char) -> bool;
        pub fn split_addresses(addresses: *const raw::c_char, ip4_addrs: *mut ovs_svec, ipv6_addrs: *mut ovs_svec);
        pub fn ip_address_and_port_from_lb_key(key: *const raw::c_char, ip_address: *mut *mut raw::c_char,
                                               port: *mut libc::uint16_t, addr_family: *mut raw::c_int);
        pub fn ovn_get_internal_version() -> *mut raw::c_char;
    }
}

mod ovs {
    use ::std::os::raw;
    use ::libc;
    use super::in6_addr_c;
    use super::ovs_be32;
    use super::ovs_ds;
    use super::eth_addr_c;
    use super::ovs_svec;

    /* functions imported from libopenvswitch */
    #[link(name = "openvswitch")]
    extern "C" {
        // lib/packets.h
        pub fn ipv6_string_mapped(addr_str: *mut raw::c_char, addr: *const in6_addr_c) -> *const raw::c_char;
        pub fn ipv6_parse_masked(s: *const raw::c_char, ip: *mut in6_addr_c, mask: *mut in6_addr_c) -> *mut raw::c_char;
        pub fn ipv6_parse_cidr(s: *const raw::c_char, ip: *mut in6_addr_c, plen: *mut raw::c_uint) -> *mut raw::c_char;
        pub fn ipv6_parse(s: *const raw::c_char, ip: *mut in6_addr_c) -> bool;
        pub fn ip_parse_masked(s: *const raw::c_char, ip: *mut ovs_be32, mask: *mut ovs_be32) -> *mut raw::c_char;
        pub fn ip_parse_cidr(s: *const raw::c_char, ip: *mut ovs_be32, plen: *mut raw::c_uint) -> *mut raw::c_char;
        pub fn ip_parse(s: *const raw::c_char, ip: *mut ovs_be32) -> bool;
        pub fn eth_addr_from_string(s: *const raw::c_char, ea: *mut eth_addr_c) -> bool;

        // include/openvswitch/json.h
        pub fn json_string_escape(str: *const raw::c_char, out: *mut ovs_ds);
        // openvswitch/dynamic-string.h
        pub fn ds_destroy(ds: *mut ovs_ds);
        pub fn ds_cstr(ds: *const ovs_ds) -> *const raw::c_char;
        pub fn svec_destroy(v: *mut ovs_svec);
        pub fn ovs_scan(s: *const raw::c_char, format: *const raw::c_char, ...) -> bool;
        pub fn str_to_int(s: *const raw::c_char, base: raw::c_int, i: *mut raw::c_int) -> bool;
        pub fn str_to_uint(s: *const raw::c_char, base: raw::c_int, i: *mut raw::c_uint) -> bool;
    }
}

/* functions imported from libc */
#[link(name = "c")]
extern "C" {
    fn free(ptr: *mut raw::c_void);
}

/* functions imported from arp/inet6 */
extern "C" {
    fn inet_ntop(af: raw::c_int, cp: *const raw::c_void,
                 buf: *mut raw::c_char, len: libc::socklen_t) -> *const raw::c_char;
}

/*
 * Parse IPv4 address list.
 */

named!(parse_spaces<nom::types::CompleteStr, ()>,
    do_parse!(many1!(one_of!(&" \t\n\r\x0c\x0b")) >> (()) )
);

named!(parse_opt_spaces<nom::types::CompleteStr, ()>,
    do_parse!(opt!(parse_spaces) >> (()))
);

named!(parse_ipv4_range<nom::types::CompleteStr, (String, Option<String>)>,
    do_parse!(addr1: many_till!(complete!(nom::anychar), alt!(do_parse!(eof!() >> (nom::types::CompleteStr(""))) | peek!(tag!("..")) | tag!(" ") )) >>
              parse_opt_spaces >>
              addr2: opt!(do_parse!(tag!("..") >>
                                    parse_opt_spaces >>
                                    addr2: many_till!(complete!(nom::anychar), alt!(do_parse!(eof!() >> (' ')) | char!(' ')) ) >>
                                    (addr2) )) >>
              parse_opt_spaces >>
              (addr1.0.into_iter().collect(), addr2.map(|x|x.0.into_iter().collect())) )
);

named!(parse_ipv4_address_list<nom::types::CompleteStr, Vec<(String, Option<String>)>>,
    do_parse!(parse_opt_spaces >>
              ranges: many0!(parse_ipv4_range) >>
              (ranges)));

pub fn parse_ip_list(ips: &String) -> ddlog_std::Either<String, ddlog_std::Vec<ddlog_std::tuple2<in_addr, ddlog_std::Option<in_addr>>>>
{
    match parse_ipv4_address_list(nom::types::CompleteStr(ips.as_str())) {
        Err(e) => {
            ddlog_std::Either::Left{l: format!("invalid IP list format: \"{}\"", ips.as_str())}
        },
        Ok((nom::types::CompleteStr(""), ranges)) => {
            let mut res = vec![];
            for (ip1, ip2) in ranges.iter() {
                let start = match ip_parse(&ip1) {
                    ddlog_std::Option::None => return ddlog_std::Either::Left{l: format!("invalid IP address: \"{}\"", *ip1)},
                    ddlog_std::Option::Some{x: ip} => ip
                };
                let end = match ip2 {
                    None => ddlog_std::Option::None,
                    Some(ip_str) => match ip_parse(&ip_str.clone()) {
                        ddlog_std::Option::None => return ddlog_std::Either::Left{l: format!("invalid IP address: \"{}\"", *ip_str)},
                        x => x
                    }
                };
                res.push(ddlog_std::tuple2(start, end));
            };
            ddlog_std::Either::Right{r: ddlog_std::Vec::from(res)}
        },
        Ok((suffix, _)) => {
            ddlog_std::Either::Left{l: format!("IP address list contains trailing characters: \"{}\"", suffix)}
        }
    }
}
