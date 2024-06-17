use btc_handshake::{
    message::{
        command::DeserializationError,
        verack::Verack,
        version::{Services, Version},
        Message,
    },
    Network, PORT_MAINNET, PROTOCOL_VERSION,
};
use clap::{builder::PossibleValue, Parser, ValueEnum};
use futures::future::join_all;
use std::{net::SocketAddr, time::SystemTime};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{lookup_host, TcpStream},
};

fn main() -> anyhow::Result<()> {
    let args = setup()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(start(args))
}

fn setup() -> anyhow::Result<Args> {
    // Initialize the tracing subscriber for logging
    tracing_subscriber::fmt::init();

    // Parse command-line arguments using the Args struct
    let args = Args::parse();

    // Return the parsed arguments
    Ok(args)
}

async fn start(args: Args) -> anyhow::Result<()> {
    tracing::info!("Resolving DNS seed: {}:{}", args.dns_seed, args.port);
    let resolved_addresses: Vec<_> = lookup_host((args.dns_seed, args.port)).await?.collect();

    let mut succeeded = 0;
    let mut failed = 0;

    for result in join_all(
        resolved_addresses
            .into_iter()
            .map(|address| tokio::time::timeout(args.timeout, handshake(&args.network.0, address))),
    )
    .await
    .into_iter()
    {
        match result {
            Ok(Ok(_)) => succeeded += 1,
            Ok(Err(e)) => {
                failed += 1;
                tracing::warn!("{}", e)
            }
            Err(e) => {
                failed += 1;
                tracing::warn!("{}", e)
            }
        }
    }
    tracing::info!("finished with {} SUCCESS & {} FAILED", succeeded, failed);

    Ok(())
}

async fn handshake(network: &Network, address: SocketAddr) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(address).await?;
    version_exchange(network, address, &mut stream).await?;
    verack_exchange(network, &mut stream).await
}

#[tracing::instrument(name = "version", skip(stream))]
async fn version_exchange(
    network: &Network,
    address: SocketAddr,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    let version = Version::new(
        PROTOCOL_VERSION,
        Services::NODE_NETWORK,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as i64,
        address,
        stream.local_addr()?,
        rand::random(),
        "".to_string(),
        0,
        false,
    )?;
    let sent_version = Message::new(network, version);
    let frame = sent_version.serialize()?;

    stream.write_all(&frame).await?;
    tracing::trace!("Sent {} bytes", frame.len());

    let mut reader = BufReader::new(stream);
    let mut received_bytes = reader.fill_buf().await?;
    let received_n = received_bytes.len();

    tracing::trace!("Received {} bytes", received_bytes.len());

    let received_version = Message::<Version>::deserialize(&mut received_bytes, network)?;

    if sent_version.payload.nonce == received_version.payload.nonce {
        Err(HandshakeError::NonceConflict)?
    }

    if sent_version.payload.version > received_version.payload.version {
        tracing::warn!("received version ({}) which is lower than the currently implemented one ({}) trying to proceed",
            sent_version.payload.version,
            received_version.payload.version);
    }

    reader.consume(received_n);

    Ok(())
}

/// Perform the `verack` part of the handshake.
///
/// According to "official" sources, the `verack` is required.
/// * https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
/// * https://en.bitcoin.it/wiki/Protocol_documentation#version
///
/// However, people report the protocol to be fine even if the `verack` is skipped.
/// * https://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
#[tracing::instrument(name = "verack", skip(stream))]
async fn verack_exchange(network: &Network, stream: &mut TcpStream) -> anyhow::Result<()> {
    let sent_verack = Message::new(network, Verack);
    let frame = sent_verack.serialize()?;
    stream.write_all(&frame).await?;
    tracing::trace!("Sent {} bytes", frame.len());

    let mut reader = BufReader::new(stream);
    let mut received_bytes = reader.fill_buf().await?;
    let received_n = received_bytes.len();
    if received_n == 0 {
        tracing::warn!("server skipped verack message");
        return Ok(());
    }

    Message::<Verack>::deserialize(&mut received_bytes, network)?;
    reader.consume(received_n);

    Ok(())
}

/// Errors that may occurrs during the handshake.
#[derive(Debug, Error)]
enum HandshakeError {
    #[error("nonce conflict")]
    NonceConflict,

    #[error(transparent)]
    DeserializationError(#[from] DeserializationError),
}

/// A wrapper over `Network` as we cannot implement foreign traits on foreign types.
#[derive(Debug, Clone)]
struct NetworkWrapper(Network);

impl ValueEnum for NetworkWrapper {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self(Network::Mainnet),
            Self(Network::Regnet),
            Self(Network::Testnet3),
            Self(Network::Signet),
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self.0 {
            Network::Mainnet => Some(PossibleValue::new("mainnet")),
            Network::Regnet => Some(PossibleValue::new("testnet")),
            Network::Testnet3 => Some(PossibleValue::new("testnet3")),
            Network::Signet => Some(PossibleValue::new("signet")),
        }
    }
}

#[derive(Debug, Parser)]
pub(crate) struct Args {
    /// Bitcoin DNS seed domain.
    dns_seed: String,

    /// Target's TCP port.
    #[arg(short, long, default_value_t = PORT_MAINNET)]
    port: u16,

    /// Handshake timeout, in seconds.
    #[arg(short, long, value_parser = parse_duration, default_value = "5")]
    timeout: std::time::Duration,

    /// Target network.
    #[arg(short, long, value_enum, default_value_t = NetworkWrapper(Network::Mainnet))]
    network: NetworkWrapper,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}
