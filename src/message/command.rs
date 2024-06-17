use std::string::FromUtf8Error;

use thiserror::Error;

/// Command maximum length, as defined in:
/// * https://github.com/bitcoin/bitcoin/blob/88b1229c134fa006d9a57e908ebebec944419347/src/protocol.h#L31
pub const COMMAND_MAX_LENGTH: usize = 12;

pub trait Command {
    /// Command name.
    const NAME: &'static str;

    /// Check if the provided slice of bytes is a valid command.
    ///
    /// To be considered a valid command:
    /// * the slice must have length equal to 12
    /// * the first bytes must match the [`Command::NAME`]
    /// * the bytes following must be `0x00`
    fn is_valid_command(bytes: &[u8]) -> bool {
        if bytes.len() != COMMAND_MAX_LENGTH {
            return false;
        }
        for (idx, c) in Self::NAME.char_indices() {
            if char::from(bytes[idx]) != c {
                return false;
            }
        }
        for idx in Self::NAME.len()..COMMAND_MAX_LENGTH {
            if bytes[idx] != 0 {
                return false;
            }
        }
        true
    }

    /// Get the byte payload for the this command.
    fn command_bytes() -> [u8; 12] {
        let mut buffer = [0u8; COMMAND_MAX_LENGTH];
        for (i, c) in Self::NAME.char_indices() {
            buffer[i] = c as u8;
        }
        buffer
    }
}

/// Serialize a command to a `Vec<u8>`. The resulting buffer should be sent over the network
/// or used in the serialization of a bigger frame.
///
/// For example, you may implement [`BtcSerialize`] for [`version::Message<Version>`](`Message`),
/// which will recursively call [`version::Version`] before sending the whole frame through the network.
pub trait SerializeBtcCommand {
    fn serialize(&self) -> Result<Vec<u8>, std::io::Error>;
}

/// A possible error when deserializing bytes into a Bitcoin type defined in this crate.
#[derive(Debug, Error)]
pub enum DeserializationError {
    #[error("magic bytes mismatch")]
    MagicBytesMismatch,

    #[error("command mismatch: expected {expected} got {received:?}")]
    CommandMismatch {
        expected: String,
        received: Result<String, FromUtf8Error>,
    },

    #[error("invalid payload size")]
    InvalidPayloadSize,

    #[error("checksum mismatch: {received} & {calculated}")]
    ChecksumMismatch {
        received: String,
        calculated: String,
    },

    #[error(transparent)]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// Deserialize from a [`io::Read`] stream.
pub trait DeserializeBtcCommand {
    /// Read from the provided stream and deserialize command.
    ///
    /// If the command is empty (like `verack`) this operation should simply return `Ok(Self)`.
    fn deserialize(data: &mut impl std::io::Read) -> Result<Self, DeserializationError>
    where
        Self: Sized;
}
