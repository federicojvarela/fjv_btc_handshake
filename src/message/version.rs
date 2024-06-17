use bitflags::bitflags;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    io::{self, Read, Write},
    mem::size_of,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::SystemTimeError,
};
use thiserror::Error;

use crate::{
    message::{DeserializationError, DeserializeBtcCommand, SerializeBtcCommand},
    sha256_sha256,
};

use super::{Command, Message, COMMAND_MAX_LENGTH};

/// User Agent's string maximum length.
pub const MAX_USER_AGENT_LENGTH: usize = 256;

/// Maximum payload size, as defined in:
/// * https://github.com/bitcoin/bitcoin/blob/60abd463ac2eaa8bc1d616d8c07880dc53d97211/src/serialize.h#L23
pub const PAYLOAD_MAX_SIZE: usize = 0x02000000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Identifies protocol version being used by the node.
    pub version: i32,

    /// Bitfield of features to be enabled for this connection.
    pub services: Services,

    /// Standard UNIX timestamp in seconds.
    pub timestamp: i64,

    /// The network address of the node receiving this message.
    pub addr_recv: NetworkAddress,

    /// Field is ignored (according to the docs at https://en.bitcoin.it/wiki/Protocol_documentation#version).
    ///
    /// This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes.
    /// The "services" field of the address would also be redundant with the second field of the version message.
    pub addr_from: NetworkAddress,

    /// Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
    pub nonce: u64,

    /// Node user agent. See [BIP 0014](https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki).
    pub user_agent: Vec<u8>,

    /// The last block received by the emitting node .
    pub start_height: i32,

    /// Whether the remote peer should announce relayed transactions or not, see [BIP 0037](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki).
    pub relay: bool,
}

impl Version {
    /// Create a new [`Version`] payload.
    pub fn new(
        version: i32,
        services: Services,
        timestamp: i64,
        addr_recv: SocketAddr,
        addr_from: SocketAddr,
        nonce: u64,
        user_agent: String,
        start_height: i32,
        relay: bool,
    ) -> Result<Self, MessageError> {
        if user_agent.len() > MAX_USER_AGENT_LENGTH {
            return Err(MessageError::UserAgentTooLong);
        }
        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv: NetworkAddress::from_socket_addr(addr_recv, services),
            addr_from: NetworkAddress::from_socket_addr(addr_from, services),
            nonce,
            user_agent: user_agent.into_bytes(),
            start_height,
            relay,
        })
    }
}

impl SerializeBtcCommand for Version {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        // User Agent > 0 will cause a reallocation
        let mut buffer = Vec::with_capacity(
            4 + /* version */
            8 + /* services */
            8 + /* timestamp */
            26 + /* addr_recv */
            26 + /* addr_from */
            8 + /* nonce */
            4 + /* start_height */
            1, /* relay */
        );
        buffer.write_i32::<LittleEndian>(self.version)?;
        buffer.write_u64::<LittleEndian>(self.services.bits())?;
        buffer.write_i64::<LittleEndian>(self.timestamp)?;
        buffer.write_all(&self.addr_recv.serialize()?)?;
        buffer.write_all(&self.addr_from.serialize()?)?;
        buffer.write_u64::<LittleEndian>(self.nonce)?;
        buffer.write_u8(self.user_agent.len() as u8)?;
        buffer.write_all(&self.user_agent)?;
        buffer.write_i32::<LittleEndian>(self.start_height)?;
        buffer.write_u8(self.relay.into())?;
        Ok(buffer)
    }
}

impl DeserializeBtcCommand for Version {
    fn deserialize(data: &mut impl Read) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        let version = data.read_i32::<LittleEndian>()?;
        let services = Services::from_bits_truncate(data.read_u64::<LittleEndian>()?);
        let timestamp = data.read_i64::<LittleEndian>()?;
        let addr_recv = NetworkAddress::deserialize(data)?.into();
        let addr_from = NetworkAddress::deserialize(data)?.into();
        let nonce = data.read_u64::<LittleEndian>()?;
        let user_agent_length = data.read_u8()? as usize;
        let mut user_agent = vec![0u8; user_agent_length];
        data.read_exact(&mut user_agent)?;
        let start_height = data.read_i32::<LittleEndian>()?;
        let relay = data.read_u8()? != 0;
        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

impl Command for Version {
    const NAME: &'static str = "version";
}

impl SerializeBtcCommand for Message<Version> {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let payload = self.payload.serialize()?;
        let checksum = sha256_sha256(&payload);

        let mut buffer = Vec::with_capacity(
            4 + /* magic */
            COMMAND_MAX_LENGTH +
            4 + /* length */
            4 + /* checksum */
            payload.len(),
        );
        buffer.write_all(self.network.magic_bytes())?;
        buffer.write_all(&Version::command_bytes())?;
        buffer.write_u32::<LittleEndian>(payload.len() as u32)?;
        buffer.write_all(&checksum)?;
        buffer.write_all(&payload)?;
        Ok(buffer)
    }
}

/// Network Address representation, closer to the one described in:
/// * https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAddress {
    services: Services,
    // Use Ipv6Addr instead of IpAddr because its closer to the docs and to avoid confusion when roundtripping
    ip: Ipv6Addr,
    port: u16,
}

impl NetworkAddress {
    /// Convert from a [`std::net::SocketAddr`] and a [`Services`]
    fn from_socket_addr(addr: SocketAddr, services: Services) -> Self {
        Self {
            services,
            ip: {
                match addr.ip() {
                    IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                    IpAddr::V6(ip) => ip,
                }
            },
            port: addr.port(),
        }
    }
}

impl SerializeBtcCommand for NetworkAddress {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer =
            Vec::with_capacity(size_of::<Services>() + 16 /* 16 * u8 */ + 2 /* u16 */);
        buffer.write_u64::<LittleEndian>(self.services.bits())?;
        buffer.write_u128::<BigEndian>(u128::from_be_bytes(self.ip.octets()))?;
        buffer.write_u16::<BigEndian>(self.port)?;
        Ok(buffer)
    }
}

impl DeserializeBtcCommand for NetworkAddress {
    fn deserialize(data: &mut impl Read) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        let services = Services::from_bits_truncate(data.read_u64::<LittleEndian>()?);
        let ip = Ipv6Addr::from(data.read_u128::<BigEndian>()?);
        let port = data.read_u16::<BigEndian>()?;
        Ok(Self { services, ip, port })
    }
}

impl From<NetworkAddress> for SocketAddr {
    fn from(value: NetworkAddress) -> Self {
        SocketAddr::new(value.ip.into(), value.port)
    }
}

/// An error that can happen when trying to create a `Message` with invalid parameters.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("User Agent cannot be longer than {MAX_USER_AGENT_LENGTH}")]
    UserAgentTooLong,

    #[error("Invalid timestamp")]
    InvalidTimestamp(#[from] SystemTimeError),
}

bitflags! {
    /// The assigned service bits, as defined in:
    /// * https://github.com/bitcoin/bitcoin/blob/88b1229c134fa006d9a57e908ebebec944419347/src/protocol.h#L274-L304
    /// * https://en.bitcoin.it/wiki/Protocol_documentation#version
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Services: u64 {
        const NODE_NETWORK = 1;
        const NODE_GETUTXO = 2;
        const NODE_BLOOM = 4;
        const NODE_WITNESS = 8;
        const NODE_XTHIN = 16;
        const NODE_COMPACT_FILTERS = 64;
        const NODE_NETWORK_LIMITED = 1024;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use quickcheck::{Arbitrary, Gen, TestResult};
    use quickcheck_macros::quickcheck;

    use crate::{
        message::{
            command::{DeserializeBtcCommand, SerializeBtcCommand},
            Command, Message,
        },
        Network, PROTOCOL_VERSION,
    };

    use super::{NetworkAddress, Services, Version, MAX_USER_AGENT_LENGTH};

    #[test]
    fn valid_command() {
        let command: [u8; 12] = [
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(Version::is_valid_command(&command));
    }

    #[test]
    fn invalid_command() {
        let command: [u8; 12] = [
            0x76, 0x64, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!Version::is_valid_command(&command));
    }

    #[test]
    fn invalid_padding() {
        let command: [u8; 12] = [
            0x76, 0x64, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        assert!(!Version::is_valid_command(&command));
    }

    impl Arbitrary for Services {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Services::from_bits_truncate(u64::arbitrary(g))
        }
    }

    impl Arbitrary for NetworkAddress {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            NetworkAddress {
                services: Services::arbitrary(g),
                ip: Ipv6Addr::new(
                    u16::arbitrary(g),
                    u16::arbitrary(g),
                    u16::arbitrary(g),
                    u16::arbitrary(g),
                    u16::arbitrary(g),
                    u16::arbitrary(g),
                    u16::arbitrary(g),
                    u16::arbitrary(g),
                ),
                port: u16::arbitrary(g),
            }
        }
    }

    #[quickcheck]
    fn fuzz_network_address_roundtrip(network_address: NetworkAddress) -> TestResult {
        let bytes = match network_address.serialize() {
            Ok(serialized) => serialized,
            Err(e) => return TestResult::error(e.to_string()),
        };

        let deserialized = match NetworkAddress::deserialize(&mut bytes.as_slice()) {
            Ok(deserialized) => deserialized,
            Err(e) => {
                return TestResult::error(e.to_string());
            }
        };

        TestResult::from_bool(deserialized == network_address)
    }

    impl Arbitrary for Version {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                version: PROTOCOL_VERSION,
                services: Services::arbitrary(g),
                timestamp: i64::arbitrary(g),
                addr_recv: NetworkAddress::arbitrary(g),
                addr_from: NetworkAddress::arbitrary(g),
                nonce: u64::arbitrary(g),
                user_agent: Vec::<u8>::arbitrary(&mut Gen::new(MAX_USER_AGENT_LENGTH)),
                start_height: i32::arbitrary(g),
                relay: bool::arbitrary(g),
            }
        }
    }

    #[quickcheck]
    fn fuzz_version_roundtrip(version: Version) -> TestResult {
        let bytes = match version.serialize() {
            Ok(serialized) => serialized,
            Err(e) => return TestResult::error(e.to_string()),
        };

        let deserialized = match Version::deserialize(&mut bytes.as_slice()) {
            Ok(deserialized) => deserialized,
            Err(e) => {
                return TestResult::error(e.to_string());
            }
        };
        TestResult::from_bool(deserialized == version)
    }

    impl Arbitrary for Message<Version> {
        fn arbitrary(g: &mut Gen) -> Self {
            Self {
                network: Network::arbitrary(g),
                payload: Version::arbitrary(g),
            }
        }
    }

    #[quickcheck]
    fn fuzz_message_version_roundtrip(message: Message<Version>) -> TestResult {
        let bytes = match message.serialize() {
            Ok(serialized) => serialized,
            Err(e) => return TestResult::error(e.to_string()),
        };

        let deserialized = match Message::deserialize(&mut bytes.as_slice(), &message.network) {
            Ok(deserialized) => deserialized,
            Err(e) => {
                return TestResult::error(e.to_string());
            }
        };
        TestResult::from_bool(deserialized == message)
    }
}
