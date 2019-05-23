#[macro_use] extern crate nom;

use differential_datalog::arcval;
use differential_datalog::record;
use std::ffi;
use std::ptr;
use std::default;
use std::process;
use libc;
use super::__std;

pub fn ovn_warn(msg: &String) {
    warn(msg.as_str())
}

pub fn ovn_abort(msg: &String) {
    abort(msg.as_str())
}

pub fn warn(msg: &str) {
    unsafe {
        ddlog_warn(ffi::CString::new(msg).unwrap().as_ptr());
    }
}

pub fn err(msg: &str) {
    unsafe {
        ddlog_err(ffi::CString::new(msg).unwrap().as_ptr());
    }
}

fn abort(msg: &str) {
    err(format!("DDlog error: {}.", msg).as_ref());
    process::abort();
}


const ETH_ADDR_SIZE:    usize = 6;
const IN6_ADDR_SIZE:    usize = 16;
const INET6_ADDRSTRLEN: usize = 46;
const INET_ADDRSTRLEN:  usize = 16;
const ETH_ADDR_STRLEN:  usize = 17;

/* Implementation for externs declared in ovn.dl */

#[repr(C)]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Serialize, Deserialize, Debug)]
pub struct ovn_eth_addr {
    x: [u8; ETH_ADDR_SIZE]
}

pub fn ovn_eth_addr_zero() -> ovn_eth_addr {
    ovn_eth_addr { x: [0; ETH_ADDR_SIZE] }
}

pub fn ovn_eth_addr2string(addr: &ovn_eth_addr) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            addr.x[0], addr.x[1], addr.x[2], addr.x[3], addr.x[4], addr.x[5])
}

pub fn ovn_eth_addr_from_string(s: &String) -> std_Option<ovn_eth_addr> {
    let mut ea: ovn_eth_addr = Default::default();
    unsafe {
        if eth_addr_from_string(string2cstr(s).as_ptr(), &mut ea as *mut ovn_eth_addr) {
            std_Option::std_Some{x: ea}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_eth_addr_from_uint64(x: &u64) -> ovn_eth_addr {
    let mut ea: ovn_eth_addr = Default::default();
    unsafe {
        eth_addr_from_uint64(*x as libc::uint64_t, &mut ea as *mut ovn_eth_addr);
        ea
    }
}

pub fn ovn_eth_addr_mark_random(ea: &ovn_eth_addr) -> ovn_eth_addr {
    unsafe {
        let mut ea_new = ea.clone();
        eth_addr_mark_random(&mut ea_new as *mut ovn_eth_addr);
        ea_new
    }
}

pub fn ovn_eth_addr_to_uint64(ea: &ovn_eth_addr) -> u64 {
    unsafe {
        eth_addr_to_uint64(ea.clone()) as u64
    }
}


impl FromRecord for ovn_eth_addr {
    fn from_record(val: &record::Record) -> Result<Self, String> {
        Ok(ovn_eth_addr{x: <[u8; ETH_ADDR_SIZE]>::from_record(val)?})
    }
}

decl_struct_into_record!(ovn_eth_addr, <>, x);
decl_record_mutator_struct!(ovn_eth_addr, <>, x: [u8; ETH_ADDR_SIZE]);


#[repr(C)]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Serialize, Deserialize, Debug)]
pub struct ovn_in6_addr {
    x: [u8; IN6_ADDR_SIZE]
}

pub const ovn_in6addr_any: ovn_in6_addr = ovn_in6_addr{x: [0; IN6_ADDR_SIZE]};

impl FromRecord for ovn_in6_addr {
    fn from_record(val: &record::Record) -> Result<Self, String> {
        Ok(ovn_in6_addr{x: <[u8; IN6_ADDR_SIZE]>::from_record(val)?})
    }
}

decl_struct_into_record!(ovn_in6_addr, <>, x);
decl_record_mutator_struct!(ovn_in6_addr, <>, x: [u8; IN6_ADDR_SIZE]);

pub fn ovn_in6_generate_lla(ea: &ovn_eth_addr) -> ovn_in6_addr {
    let mut addr: ovn_in6_addr = Default::default();
    unsafe {in6_generate_lla(ea.clone(), &mut addr as *mut ovn_in6_addr)};
    addr
}

pub fn ovn_in6_generate_eui64(ea: &ovn_eth_addr, prefix: &ovn_in6_addr) -> ovn_in6_addr {
    let mut addr: ovn_in6_addr = Default::default();
    unsafe {in6_generate_eui64(ea.clone(),
                               prefix as *const ovn_in6_addr,
                               &mut addr as *mut ovn_in6_addr)};
    addr
}

pub fn ovn_in6_is_lla(addr: &ovn_in6_addr) -> bool {
    unsafe {in6_is_lla(addr as *const ovn_in6_addr)}
}

pub fn ovn_in6_addr_solicited_node(ip6: &ovn_in6_addr) -> ovn_in6_addr
{
    let mut res: ovn_in6_addr = Default::default();
    unsafe {
        in6_addr_solicited_node(&mut res as *mut ovn_in6_addr, ip6 as *const ovn_in6_addr);
    }
    res
}

pub fn ovn_ipv6_addr_bitand(a: &ovn_in6_addr, b: &ovn_in6_addr) -> ovn_in6_addr {
    unsafe {
        ipv6_addr_bitand(a as *const ovn_in6_addr, b as *const ovn_in6_addr)
    }
}

pub fn ovn_ipv6_addr_bitxor(a: &ovn_in6_addr, b: &ovn_in6_addr) -> ovn_in6_addr {
    unsafe {
        ipv6_addr_bitxor(a as *const ovn_in6_addr, b as *const ovn_in6_addr)
    }
}

pub fn ovn_ipv6_string_mapped(addr: &ovn_in6_addr) -> String {
    let mut addr_str = [0 as i8; INET6_ADDRSTRLEN];
    unsafe {
        ipv6_string_mapped(&mut addr_str[0] as *mut raw::c_char, addr as *const ovn_in6_addr);
        cstr2string(&addr_str as *const raw::c_char)
    }
}

pub fn ovn_ipv6_mask_is_any(mask: &ovn_in6_addr) -> bool {
    *mask == ovn_in6addr_any
}

pub fn ovn_json_string_escape(s: &String) -> String {
    let mut ds = ovs_ds::new();
    unsafe {
        json_string_escape(ffi::CString::new(s.as_str()).unwrap().as_ptr() as *const raw::c_char,
                           &mut ds as *mut ovs_ds);
    };
    unsafe{ds.into_string()}
}

pub fn ovn_extract_lsp_addresses(address: &String) -> std_Option<ovn_lport_addresses> {
    unsafe {
        let mut laddrs: lport_addresses = Default::default();
        if extract_lsp_addresses(string2cstr(address).as_ptr(),
                                 &mut laddrs as *mut lport_addresses) {
            std_Option::std_Some{x: laddrs.into_ddlog()}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_extract_addresses(address: &String) -> std_Option<ovn_lport_addresses> {
    unsafe {
        let mut laddrs: lport_addresses = Default::default();
        let mut ofs: raw::c_int = 0;
        if extract_addresses(string2cstr(address).as_ptr(),
                             &mut laddrs as *mut lport_addresses,
                             &mut ofs as *mut raw::c_int) {
            std_Option::std_Some{x: laddrs.into_ddlog()}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_extract_lrp_networks(mac: &String, networks: &std_Set<String>) -> std_Option<ovn_lport_addresses>
{
    unsafe {
        let mut laddrs: lport_addresses = Default::default();
        let mut networks_cstrs = Vec::with_capacity(networks.x.len());
        let mut networks_ptrs = Vec::with_capacity(networks.x.len());
        for net in networks.x.iter() {
            networks_cstrs.push(string2cstr(net));
            networks_ptrs.push(networks_cstrs.last().unwrap().as_ptr());
        };
        if extract_lrp_networks__(string2cstr(mac).as_ptr(), networks_ptrs.as_ptr() as *const *const raw::c_char,
                                   networks_ptrs.len(), &mut laddrs as *mut lport_addresses) {
            std_Option::std_Some{x: laddrs.into_ddlog()}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_ipv6_parse_masked(s: &String) -> std_Either<String, (ovn_in6_addr, ovn_in6_addr)>
{
    unsafe {
        let mut ip: ovn_in6_addr = Default::default();
        let mut mask: ovn_in6_addr = Default::default();
        let err = ipv6_parse_masked(string2cstr(s).as_ptr(), &mut ip as *mut ovn_in6_addr, &mut mask as *mut ovn_in6_addr);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            std_Either::std_Left{l: errstr}
        } else {
            std_Either::std_Right{r: (ip, mask)}
        }
    }
}

pub fn ovn_ipv6_parse_cidr(s: &String) -> std_Either<String, (ovn_in6_addr, u32)>
{
    unsafe {
        let mut ip: ovn_in6_addr = Default::default();
        let mut plen: raw::c_uint = 0;
        let err = ipv6_parse_cidr(string2cstr(s).as_ptr(), &mut ip as *mut ovn_in6_addr, &mut plen as *mut raw::c_uint);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            std_Either::std_Left{l: errstr}
        } else {
            std_Either::std_Right{r: (ip, plen as u32)}
        }
    }
}

pub fn ovn_ipv6_parse(s: &String) -> std_Option<ovn_in6_addr>
{
    unsafe {
        let mut ip: ovn_in6_addr = Default::default();
        let res = ipv6_parse(string2cstr(s).as_ptr(), &mut ip as *mut ovn_in6_addr);
        if (res) {
            std_Option::std_Some{x: ip}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_ipv6_create_mask(mask: &u32) -> ovn_in6_addr
{
    unsafe {ipv6_create_mask(*mask as raw::c_uint)}
}


pub fn ovn_ipv6_is_zero(a: &ovn_in6_addr) -> bool
{
    unsafe{ipv6_is_zero(a as *const ovn_in6_addr)}
}

pub fn ovn_ipv6_multicast_to_ethernet(ip6: &ovn_in6_addr) -> ovn_eth_addr
{
    let mut eth: ovn_eth_addr = Default::default();
    unsafe{
        ipv6_multicast_to_ethernet(&mut eth as *mut ovn_eth_addr, ip6 as *const ovn_in6_addr);
    }
    eth
}

pub fn ovn_ip_parse_masked(s: &String) -> std_Either<String, (ovn_ovs_be32, ovn_ovs_be32)>
{
    unsafe {
        let mut ip: ovn_ovs_be32 = 0;
        let mut mask: ovn_ovs_be32 = 0;
        let err = ip_parse_masked(string2cstr(s).as_ptr(), &mut ip as *mut ovn_ovs_be32, &mut mask as *mut ovn_ovs_be32);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            std_Either::std_Left{l: errstr}
        } else {
            std_Either::std_Right{r: (ip, mask)}
        }
    }
}

pub fn ovn_ip_parse_cidr(s: &String) -> std_Either<String, (ovn_ovs_be32, u32)>
{
    unsafe {
        let mut ip: ovn_ovs_be32 = 0;
        let mut plen: raw::c_uint = 0;
        let err = ip_parse_cidr(string2cstr(s).as_ptr(), &mut ip as *mut ovn_ovs_be32, &mut plen as *mut raw::c_uint);
        if (err != ptr::null_mut()) {
            let errstr = cstr2string(err);
            free(err as *mut raw::c_void);
            std_Either::std_Left{l: errstr}
        } else {
            std_Either::std_Right{r: (ip, plen as u32)}
        }
    }
}

pub fn ovn_ip_parse(s: &String) -> std_Option<ovn_ovs_be32>
{
    unsafe {
        let mut ip: ovn_ovs_be32 = 0;
        if (ip_parse(string2cstr(s).as_ptr(), &mut ip as *mut ovn_ovs_be32)) {
            std_Option::std_Some{x:ip}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_is_dynamic_lsp_address(address: &String) -> bool {
    unsafe {
        is_dynamic_lsp_address(string2cstr(address).as_ptr())
    }
}

pub fn ovn_split_addresses(addresses: &String) -> (std_Set<String>, std_Set<String>) {
    let mut ip4_addrs = ovs_svec::new();
    let mut ip6_addrs = ovs_svec::new();
    unsafe {
        split_addresses(string2cstr(addresses).as_ptr(), &mut ip4_addrs as *mut ovs_svec, &mut ip6_addrs as *mut ovs_svec);
        (ip4_addrs.into_strings(), ip6_addrs.into_strings())
    }
}

pub fn ovn_scan_eth_addr(s: &String) -> std_Option<ovn_eth_addr> {
    let mut ea = ovn_eth_addr_zero();
    unsafe {
        if ovs_scan(string2cstr(s).as_ptr(), b"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\0".as_ptr() as *const raw::c_char,
                    &mut ea.x[0] as *mut u8, &mut ea.x[1] as *mut u8,
                    &mut ea.x[2] as *mut u8, &mut ea.x[3] as *mut u8,
                    &mut ea.x[4] as *mut u8, &mut ea.x[5] as *mut u8)
        {
            std_Option::std_Some{x: ea}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_scan_eth_addr_prefix(s: &String) -> std_Option<u64> {
    let mut b2: u8 = 0;
    let mut b1: u8 = 0;
    let mut b0: u8 = 0;
    unsafe {
        if ovs_scan(string2cstr(s).as_ptr(), b"%hhx:%hhx:%hhx\0".as_ptr() as *const raw::c_char,
                    &mut b2 as *mut u8, &mut b1 as *mut u8, &mut b0 as *mut u8)
        {
            std_Option::std_Some{x: ((b2 as u64) << 40) | ((b1 as u64) << 32) | ((b0 as u64) << 24) }
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_scan_static_dynamic_ip(s: &String) -> std_Option<ovn_ovs_be32> {
    let mut ip0: u8 = 0;
    let mut ip1: u8 = 0;
    let mut ip2: u8 = 0;
    let mut ip3: u8 = 0;
    let mut n: raw::c_uint = 0;
    unsafe {
        if ovs_scan(string2cstr(s).as_ptr(), b"dynamic %hhu.%hhu.%hhu.%hhu%n\0".as_ptr() as *const raw::c_char,
                    &mut ip0 as *mut u8,
                    &mut ip1 as *mut u8,
                    &mut ip2 as *mut u8,
                    &mut ip3 as *mut u8,
                    &mut n) && s.len() == (n as usize)
        {
            std_Option::std_Some{x: std_htonl(&(((ip0 as u32) << 24)  | ((ip1 as u32) << 16) | ((ip2 as u32) << 8) | (ip3 as u32)))}
        } else {
            std_Option::std_None
        }
    }
}

pub fn ovn_ip_address_and_port_from_lb_key(k: &String) ->
    std_Option<(String, u16, u32)> {
        unsafe {
        let mut ip_address: *mut raw::c_char = ptr::null_mut();
        let mut port: libc::uint16_t = 0;
        let mut addr_family: raw::c_int = 0;

        ip_address_and_port_from_lb_key(string2cstr(k).as_ptr(), &mut ip_address as *mut *mut raw::c_char,
                                &mut port as *mut libc::uint16_t, &mut addr_family as *mut raw::c_int);
        if (ip_address == ptr::null_mut()) {
            std_Option::std_None
        } else {
            let res = (cstr2string(ip_address), port as u16, addr_family as u32);
            free(ip_address as *mut raw::c_void);
            std_Option::std_Some{x: res}
        }
    }
}

pub fn ovn_count_1bits(x: &u64) -> u8 {
    unsafe { count_1bits(*x as libc::uint64_t) as u8 }
}


pub fn ovn_str_to_int(s: &String, base: &u16) -> std_Option<u64> {
    let mut i: raw::c_int = 0;
    let ok = unsafe {
        str_to_int(string2cstr(s).as_ptr(), *base as raw::c_int, &mut i as *mut raw::c_int)
    };
    if ok {
        std_Option::std_Some{x: i as u64}
    } else {
        std_Option::std_None
    }
}

pub fn ovn_inet6_ntop(addr: &ovn_in6_addr) -> String {
    let mut buf = [0 as i8; INET6_ADDRSTRLEN];
    unsafe {
        let res = inet_ntop(ovn_aF_INET6() as raw::c_int, addr as *const ovn_in6_addr as *const raw::c_void,
                            &mut buf[0] as *mut raw::c_char, INET6_ADDRSTRLEN as libc::socklen_t);
        if res == ptr::null() {
            warn(format!("inet_ntop({:?}) failed", *addr).as_ref());
            "".to_owned()
        } else {
            cstr2string(&buf as *const raw::c_char)
        }
    }
}

/* Internals */

unsafe fn cstr2string(s: *const raw::c_char) -> String {
    ffi::CStr::from_ptr(s).to_owned().into_string().
        unwrap_or_else(|e|{ warn(format!("cstr2string: {}", e).as_ref()); "".to_owned() })
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
        let res = cstr2string(ds_cstr(&self as *const ovs_ds));
        ds_destroy(&mut self as *mut ovs_ds);
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

    pub unsafe fn into_strings(mut self) -> std_Set<String> {
        let mut res: std_Set<String> = std_Set::new();
        unsafe {
            for i in 0..self.n {
                res.insert(cstr2string(*self.names.offset(i as isize)));
            }
            svec_destroy(&mut self as *mut ovs_svec);
        }
        res
    }
}


// ovn/lib/ovn-util.h
#[repr(C)]
struct ipv4_netaddr {
    addr:       libc::uint32_t,
    mask:       libc::uint32_t,
    network:    libc::uint32_t,
    plen:       raw::c_uint,

    addr_s:     [raw::c_char; INET_ADDRSTRLEN + 1],  /* "192.168.10.123" */
    network_s:  [raw::c_char; INET_ADDRSTRLEN + 1],  /* "192.168.10.0" */
    bcast_s:    [raw::c_char; INET_ADDRSTRLEN + 1]   /* "192.168.10.255" */
}

impl Default for ipv4_netaddr {
    fn default() -> Self {
        ipv4_netaddr {
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

impl ipv4_netaddr {
    pub unsafe fn to_ddlog(&self) -> ovn_ipv4_netaddr {
        ovn_ipv4_netaddr{
            addr:       self.addr,
            mask:       self.mask,
            network:    self.network,
            plen:       self.plen,
            addr_s:     cstr2string(&self.addr_s as *const raw::c_char),
            network_s:  cstr2string(&self.network_s as *const raw::c_char),
            bcast_s:    cstr2string(&self.bcast_s as *const raw::c_char)
        }
    }
}

#[repr(C)]
struct ipv6_netaddr {
    addr:       ovn_in6_addr,     /* fc00::1 */
    mask:       ovn_in6_addr,     /* ffff:ffff:ffff:ffff:: */
    sn_addr:    ovn_in6_addr,     /* ff02:1:ff00::1 */
    network:    ovn_in6_addr,     /* fc00:: */
    plen:       raw::c_uint,      /* CIDR Prefix: 64 */

    addr_s:     [raw::c_char; INET6_ADDRSTRLEN + 1],    /* "fc00::1" */
    sn_addr_s:  [raw::c_char; INET6_ADDRSTRLEN + 1],    /* "ff02:1:ff00::1" */
    network_s:  [raw::c_char; INET6_ADDRSTRLEN + 1]     /* "fc00::" */
}

impl Default for ipv6_netaddr {
    fn default() -> Self {
        ipv6_netaddr {
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

impl ipv6_netaddr {
    pub unsafe fn to_ddlog(&self) -> ovn_ipv6_netaddr {
        ovn_ipv6_netaddr{
            addr:       self.addr.clone(),
            mask:       self.mask.clone(),
            sn_addr:    self.sn_addr.clone(),
            network:    self.network.clone(),
            plen:       self.plen,
            addr_s:     cstr2string(&self.addr_s as *const raw::c_char),
            sn_addr_s:  cstr2string(&self.sn_addr_s as *const raw::c_char),
            network_s:  cstr2string(&self.network_s as *const raw::c_char)
        }
    }
}


// ovn-util.h
#[repr(C)]
struct lport_addresses {
    ea_s:           [raw::c_char; ETH_ADDR_STRLEN + 1],
    ea:             ovn_eth_addr,
    n_ipv4_addrs:   libc::size_t,
    ipv4_addrs:     *mut ipv4_netaddr,
    n_ipv6_addrs:   libc::size_t,
    ipv6_addrs:     *mut ipv6_netaddr
}

impl Default for lport_addresses {
    fn default() -> Self {
        lport_addresses {
            ea_s:           [0; ETH_ADDR_STRLEN + 1],
            ea:             Default::default(),
            n_ipv4_addrs:   0,
            ipv4_addrs:     ptr::null_mut(),
            n_ipv6_addrs:   0,
            ipv6_addrs:     ptr::null_mut()
        }
    }
}

impl lport_addresses {
    pub unsafe fn into_ddlog(mut self) -> ovn_lport_addresses {
        let mut ipv4_addrs = std_Vec::with_capacity(self.n_ipv4_addrs);
        for i in 0..self.n_ipv4_addrs {
            ipv4_addrs.push((&*self.ipv4_addrs.offset(i as isize)).to_ddlog())
        }
        let mut ipv6_addrs = std_Vec::with_capacity(self.n_ipv6_addrs);
        for i in 0..self.n_ipv6_addrs {
            ipv6_addrs.push((&*self.ipv6_addrs.offset(i as isize)).to_ddlog())
        }
        let res = ovn_lport_addresses {
            ea_s:       cstr2string(&self.ea_s as *const raw::c_char),
            ea:         self.ea.clone(),
            ipv4_addrs: ipv4_addrs,
            ipv6_addrs: ipv6_addrs
        };
        destroy_lport_addresses(&mut self as *mut lport_addresses);
        res
    }
}

/* functions imported from ovn-northd.c */
extern "C" {
    fn ddlog_warn(msg: *const raw::c_char);
    fn ddlog_err(msg: *const raw::c_char);
}

/* functions imported from libovn */
#[link(name = "ovn")]
extern "C" {
    // ovn/lib/ovn-util.h
    fn extract_lsp_addresses(address: *const raw::c_char, laddrs: *mut lport_addresses) -> bool;
    fn extract_addresses(address: *const raw::c_char, laddrs: *mut lport_addresses, ofs: *mut raw::c_int) -> bool;
    fn extract_lrp_networks__(mac: *const raw::c_char, networks: *const *const raw::c_char,
                               n_networks: libc::size_t, laddrs: *mut lport_addresses) -> bool;
    fn destroy_lport_addresses(addrs: *mut lport_addresses);
    fn is_dynamic_lsp_address(address: *const raw::c_char) -> bool;
    fn split_addresses(addresses: *const raw::c_char, ip4_addrs: *mut ovs_svec, ipv6_addrs: *mut ovs_svec);
    fn ip_address_and_port_from_lb_key(key: *const raw::c_char, ip_address: *mut *mut raw::c_char,
                                port: *mut libc::uint16_t, addr_family: *mut raw::c_int);
}

/* functions imported from libopenvswitch */
#[link(name = "openvswitch")]
extern "C" {
    // lib/packets.h
    fn ipv6_string_mapped(addr_str: *mut raw::c_char, addr: *const ovn_in6_addr) -> *const raw::c_char;
    fn ipv6_parse_masked(s: *const raw::c_char, ip: *mut ovn_in6_addr, mask: *mut ovn_in6_addr) -> *mut raw::c_char;
    fn ipv6_parse_cidr(s: *const raw::c_char, ip: *mut ovn_in6_addr, plen: *mut raw::c_uint) -> *mut raw::c_char;
    fn ipv6_parse(s: *const raw::c_char, ip: *mut ovn_in6_addr) -> bool;
    fn ipv6_mask_is_any(mask: *const ovn_in6_addr) -> bool;
    fn ipv6_addr_bitxor(a: *const ovn_in6_addr, b: *const ovn_in6_addr) -> ovn_in6_addr;
    fn ipv6_addr_bitand(a: *const ovn_in6_addr, b: *const ovn_in6_addr) -> ovn_in6_addr;
    fn ipv6_create_mask(mask: raw::c_uint) -> ovn_in6_addr;
    fn ipv6_is_zero(a: *const ovn_in6_addr) -> bool;
    fn ipv6_multicast_to_ethernet(eth: *mut ovn_eth_addr, ip6: *const ovn_in6_addr);
    fn ip_parse_masked(s: *const raw::c_char, ip: *mut ovn_ovs_be32, mask: *mut ovn_ovs_be32) -> *mut raw::c_char;
    fn ip_parse_cidr(s: *const raw::c_char, ip: *mut ovn_ovs_be32, plen: *mut raw::c_uint) -> *mut raw::c_char;
    fn ip_parse(s: *const raw::c_char, ip: *mut ovn_ovs_be32) -> bool;
    fn eth_addr_from_string(s: *const raw::c_char, ea: *mut ovn_eth_addr) -> bool;
    fn eth_addr_to_uint64(ea: ovn_eth_addr) -> libc::uint64_t;
    fn eth_addr_from_uint64(x: libc::uint64_t, ea: *mut ovn_eth_addr);
    fn eth_addr_mark_random(ea: *mut ovn_eth_addr);
    fn in6_generate_eui64(ea: ovn_eth_addr, prefix: *const ovn_in6_addr, lla: *mut ovn_in6_addr);
    fn in6_generate_lla(ea: ovn_eth_addr, lla: *mut ovn_in6_addr);
    fn in6_is_lla(addr: *const ovn_in6_addr) -> bool;
    fn in6_addr_solicited_node(addr: *mut ovn_in6_addr, ip6: *const ovn_in6_addr);

    // include/openvswitch/json.h
    fn json_string_escape(str: *const raw::c_char, out: *mut ovs_ds);
    // openvswitch/dynamic-string.h
    fn ds_destroy(ds: *mut ovs_ds);
    fn ds_cstr(ds: *const ovs_ds) -> *const raw::c_char;
    fn svec_destroy(v: *mut ovs_svec);
    fn ovs_scan(s: *const raw::c_char, format: *const raw::c_char, ...) -> bool;
    fn count_1bits(x: libc::uint64_t) -> raw::c_uint;
    fn str_to_int(s: *const raw::c_char, base: raw::c_int, i: *mut raw::c_int) -> bool;
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

pub fn ovn_parse_ip_list(ips: &String) -> std_Either<String, std_Vec<(ovn_ovs_be32, std_Option<ovn_ovs_be32>)>>
{
    match parse_ipv4_address_list(nom::types::CompleteStr(ips.as_str())) {
        Err(e) => {
            std_Either::std_Left{l: format!("invalid IP list format: \"{}\"", ips.as_str())}
        },
        Ok((nom::types::CompleteStr(""), ranges)) => {
            let mut res = vec![];
            for (ip1, ip2) in ranges.iter() {
                let start = match ovn_ip_parse(&ip1) {
                    std_Option::std_None => return std_Either::std_Left{l: format!("invalid IP address: \"{}\"", *ip1)},
                    std_Option::std_Some{x: ip} => ip
                };
                let end = match ip2 {
                    None => std_Option::std_None,
                    Some(ip_str) => match ovn_ip_parse(&ip_str.clone()) {
                        std_Option::std_None => return std_Either::std_Left{l: format!("invalid IP address: \"{}\"", *ip_str)},
                        x => x
                    }
                };
                res.push((start, end));
            };
            std_Either::std_Right{r: std_Vec{x: res}}
        },
        Ok((suffix, _)) => {
            std_Either::std_Left{l: format!("IP address list contains trailing characters: \"{}\"", suffix)}
        }
    }
}
