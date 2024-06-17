use crate::message::DeserializationError;

use super::Command;
use super::DeserializeBtcCommand;
use super::SerializeBtcCommand;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verack;

impl Command for Verack {
    const NAME: &'static str = "verack";
}

impl SerializeBtcCommand for Verack {
    fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        Ok(vec![])
    }
}

impl DeserializeBtcCommand for Verack {
    fn deserialize(_: &mut impl std::io::Read) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        Ok(Verack)
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::{Arbitrary, TestResult};
    use quickcheck_macros::quickcheck;

    use crate::{
        message::{Command, Message},
        Network,
    };

    use super::Verack;

    #[test]
    fn valid_command() {
        let command: [u8; 12] = [
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(Verack::is_valid_command(&command));
    }

    #[test]
    fn invalid_command() {
        let command: [u8; 12] = [
            0x76, 0x64, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!Verack::is_valid_command(&command));
    }

    #[test]
    fn invalid_padding() {
        let command: [u8; 12] = [
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        assert!(!Verack::is_valid_command(&command));
    }

    impl Arbitrary for Message<Verack> {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                network: Network::arbitrary(g),
                payload: Verack,
            }
        }
    }

    #[quickcheck]
    fn fuzz_message_verack_roundtrip(message: Message<Verack>) -> TestResult {
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
