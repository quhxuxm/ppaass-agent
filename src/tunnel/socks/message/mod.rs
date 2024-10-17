mod auth;
mod init;
mod udp;
use std::fmt::Display;
use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ppaass_protocol::message::values::address::UnifiedAddress;
pub(crate) use auth::*;
pub(crate) use init::*;
pub(crate) use udp::*;
use crate::error::AgentServerError;
const IPV4_FLAG: u8 = 1;
const IPV6_FLAG: u8 = 4;
const DOMAIN_FLAG: u8 = 3;

#[derive(Debug, Clone)]
pub(crate) enum Socks5Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Socks5Address {
    pub(crate) fn parse(input: &mut impl Buf) -> Result<Socks5Address, AgentServerError> {
        if !input.has_remaining() {
            return Err(AgentServerError::Other(
                "Input bytes exhausted, remaining: 0".to_string(),
            ));
        }
        let address_type = input.get_u8();
        let address = match address_type {
            IPV4_FLAG => {
                if input.remaining() < 6 {
                    return Err(AgentServerError::Other(format!(
                        "Input bytes exhausted, remaining: {}, require: 6",
                        input.remaining()
                    )));
                }
                Socks5Address::Ip(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(
                        input.get_u8(),
                        input.get_u8(),
                        input.get_u8(),
                        input.get_u8(),
                    ),
                    input.get_u16(),
                )))
            }
            IPV6_FLAG => {
                if input.remaining() < 18 {
                    return Err(AgentServerError::Other(format!(
                        "Input bytes exhausted, remaining: {}, require: 18",
                        input.remaining()
                    )));
                }
                Socks5Address::Ip(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(
                        input.get_u16(),
                        input.get_u16(),
                        input.get_u16(),
                        input.get_u16(),
                        input.get_u16(),
                        input.get_u16(),
                        input.get_u16(),
                        input.get_u16(),
                    ),
                    input.get_u16(),
                    0,
                    0,
                )))
            }
            DOMAIN_FLAG => {
                if input.remaining() < 1 {
                    return Err(AgentServerError::Other(format!(
                        "Input bytes exhausted, remaining: {}, require: 1",
                        input.remaining()
                    )));
                }
                let domain_name_length = input.get_u8() as usize;
                if input.remaining() < domain_name_length + 2 {
                    return Err(AgentServerError::Other(format!(
                        "Input bytes exhausted, remaining: {}, require: {}",
                        input.remaining(),
                        domain_name_length + 2
                    )));
                }
                let domain_name_bytes = input.copy_to_bytes(domain_name_length);
                let domain_name = match String::from_utf8_lossy(domain_name_bytes.chunk())
                    .to_string()
                    .as_str()
                {
                    "0" => "127.0.0.1".to_string(),
                    v => v.to_string(),
                };
                let port = input.get_u16();
                Socks5Address::Domain(domain_name, port)
            }
            unknown_addr_type => {
                return Err(AgentServerError::Other(format!(
                    "Invalid address type: {unknown_addr_type}"
                )));
            }
        };
        Ok(address)
    }
}

impl TryFrom<Socks5Address> for SocketAddr {
    type Error = AgentServerError;

    fn try_from(socks5_addr: Socks5Address) -> Result<Self, Self::Error> {
        match socks5_addr {
            Socks5Address::Ip(socket_address) => Ok(socket_address),
            Socks5Address::Domain(host, port) => {
                let address_string = format!("{host}:{port}");
                let addresses = address_string.to_socket_addrs()?.collect::<Vec<_>>();
                let result = addresses.first().ok_or(AgentServerError::Other(format!(
                    "Can not convert domain to socket address: {address_string}"
                )))?;
                Ok(*result)
            }
        }
    }
}

impl From<SocketAddr> for Socks5Address {
    fn from(socket_addr: SocketAddr) -> Self {
        Socks5Address::Ip(socket_addr)
    }
}

impl Display for Socks5Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::Ip(socket_addr) => {
                format!("{socket_addr}")
            }
            Self::Domain(host, port) => {
                format!("{host}:{port}")
            }
        };
        write!(f, "{}", str)
    }
}

impl From<Socks5Address> for Bytes {
    fn from(address: Socks5Address) -> Self {
        let mut result = BytesMut::new();
        match address {
            Socks5Address::Ip(socket_addr) => match socket_addr {
                SocketAddr::V4(ip_v4_addr) => {
                    result.put_u8(IPV4_FLAG);
                    result.put_slice(&ip_v4_addr.ip().octets());
                    result.put_u16(ip_v4_addr.port());
                }
                SocketAddr::V6(ip_v6_addr) => {
                    result.put_u8(IPV6_FLAG);
                    result.put_slice(&ip_v6_addr.ip().octets());
                    result.put_u16(ip_v6_addr.port());
                }
            },
            Socks5Address::Domain(addr_content, port) => {
                result.put_u8(DOMAIN_FLAG);
                result.put_u8(addr_content.len() as u8);
                result.put_slice(addr_content.as_bytes());
                result.put_u16(port);
            }
        }
        result.into()
    }
}

impl From<Socks5Address> for UnifiedAddress {
    fn from(value: Socks5Address) -> Self {
        match value {
            Socks5Address::Ip(socket_addr) => UnifiedAddress::Ip(socket_addr),
            Socks5Address::Domain(host, port) => UnifiedAddress::Domain { host, port },
        }
    }
}

impl TryFrom<UnifiedAddress> for Socks5Address {
    type Error = AgentServerError;
    fn try_from(net_addr: UnifiedAddress) -> Result<Self, Self::Error> {
        match net_addr {
            UnifiedAddress::Ip(socket_addr) => Ok(Socks5Address::Ip(socket_addr)),
            UnifiedAddress::Domain { host, port } => Ok(Socks5Address::Domain(host, port)),
        }
    }
}
