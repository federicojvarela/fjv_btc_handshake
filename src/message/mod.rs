pub mod command;
pub mod verack;
pub mod version;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Write};

use crate::{sha256_sha256, Network};

use self::{
    command::{
        Command, DeserializationError, DeserializeBtcCommand, SerializeBtcCommand,
        COMMAND_MAX_LENGTH,
    },
    version::PAYLOAD_MAX_SIZE,
};

#[derive(Clone, Debug, PartialEq, Eq)]
/// A Bitcoin protocol message header.
pub struct Message<T: Command> {
    /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown.
    pub network: Network,

    /// The message payload.
    pub payload: T,
}

impl<T> Message<T>
where
    T: Command,
{
    /// Build a new [`Message`] using the provided [`Network`] and payload.
    pub fn new(network: &Network, payload: T) -> Self {
        Self {
            network: network.clone(),
            payload,
        }
    }
}

impl<T> Message<T>
where
    T: Command + SerializeBtcCommand + DeserializeBtcCommand,
{
    /// Deserialize/parse a [`Message`].
    pub fn deserialize(
        data: &mut impl io::Read,
        network: &Network,
    ) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        let mut magic = [0u8; 4];
        data.read_exact(&mut magic)?;
        if magic != *network.magic_bytes() {
            return Err(DeserializationError::MagicBytesMismatch);
        }

        let mut command_name = [0u8; COMMAND_MAX_LENGTH];
        data.read_exact(&mut command_name)?;
        if !T::is_valid_command(&command_name) {
            return Err(DeserializationError::CommandMismatch {
                expected: T::NAME.to_string(),
                // Returning the Result since panicking in an error would be... less than ideal
                received: String::from_utf8(command_name.to_vec()),
            });
        }

        let payload_length = data.read_u32::<LittleEndian>()? as usize;
        if payload_length > PAYLOAD_MAX_SIZE {
            return Err(DeserializationError::InvalidPayloadSize);
        }

        let mut received_checksum = [0u8; 4];
        data.read_exact(&mut received_checksum)?;

        // If the payload_length == 0 there's no allocation, thus no actual read
        // so we just perform the checksum for strictness
        let mut payload = vec![0u8; payload_length];
        data.read_exact(&mut payload)?;

        let calculated_checksum = sha256_sha256(&payload);

        if received_checksum != calculated_checksum {
            return Err(DeserializationError::ChecksumMismatch {
                received: format!("{:#x}", i32::from_ne_bytes(received_checksum)),
                calculated: format!("{:#x}", i32::from_ne_bytes(calculated_checksum)),
            });
        }

        Ok(Self {
            network: network.clone(),
            payload: T::deserialize(&mut payload.as_slice())?,
        })
    }

    /// Serialize a [`Message`].
    pub fn serialize(&self) -> Result<Vec<u8>, io::Error> {
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
        buffer.write_all(&T::command_bytes())?;
        buffer.write_u32::<LittleEndian>(payload.len() as u32)?;
        buffer.write_all(&checksum)?;
        if payload.len() != 0 {
            buffer.write_all(&payload)?;
        }
        Ok(buffer)
    }
}
