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

async fn resolve_dns_seed(dns_seed: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    // Log the action of resolving the DNS seed with the specified port
    tracing::info!("Resolving DNS seed: {}:{}", dns_seed, port);

    // Perform the DNS lookup asynchronously, handling errors with a custom message
    let resolved_addresses = lookup_host((dns_seed, port)).await
        .map_err(|e| {
            // If an error occurs, return a detailed error using anyhow's anyhow! macro
            anyhow::anyhow!("Failed to resolve DNS seed '{}:{}': {}", dns_seed, port, e)
        })?
        .collect(); // Collect the results into a vector of SocketAddr

    // Return the resolved addresses if successful
    Ok(resolved_addresses)
}

// Function to perform handshakes with a list of resolved addresses
async fn perform_handshakes(
    resolved_addresses: Vec<SocketAddr>,
    args: &Args,
) -> anyhow::Result<()> {
    // Map each address to a handshake attempt with a timeout
    let handshakes = resolved_addresses
        .into_iter()
        .map(|address| tokio::time::timeout(args.timeout, handshake(&args.network.0, address)));

    // Await all handshake attempts and collect results
    let results = join_all(handshakes).await;

    // Count the number of succeeded and failed handshakes
    let (succeeded, failed) = results.into_iter().fold((0, 0), |(succ, fail), result| {
        match result {
            Ok(Ok(_)) => (succ + 1, fail), // Increment success count if handshake succeeded
            Ok(Err(e)) => {
                tracing::warn!("Handshake error: {}", e); // Log warning if handshake failed
                (succ, fail + 1) // Increment failure count
            }
            Err(e) => {
                tracing::warn!("Timeout error: {}", e); // Log warning if handshake timed out
                (succ, fail + 1) // Increment failure count
            }
        }
    });

    // Log the final results of all handshakes
    tracing::info!(
        "Handshake results: {} succeeded, {} failed",
        succeeded,
        failed
    );
    Ok(())
}

async fn start(args: Args) -> anyhow::Result<()> {
    let resolved_addresses = resolve_dns_seed(&args.dns_seed, args.port).await?;
    perform_handshakes(resolved_addresses, &args).await?;
    Ok(())
}

async fn handshake(network: &Network, address: SocketAddr) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(address).await?;
    version_exchange(network, address, &mut stream).await?;
    verack_exchange(network, &mut stream).await
}

#[tracing::instrument(name = "version_exchange", skip(stream))]
async fn version_exchange(
    network: &Network,
    address: SocketAddr,
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    // Construct the version message to send
    let version_message = create_version_message(network, PROTOCOL_VERSION as u32, address, stream)?;
    let serialized_message = version_message.serialize()?;

    // Send the serialized version message
    stream.write_all(&serialized_message).await?;
    tracing::trace!("Sent {} bytes", serialized_message.len());

    // Receive and process the response
    let mut reader = BufReader::new(stream);
    let mut buffer = reader.fill_buf().await?;
    let received_length = buffer.len();
    tracing::trace!("Received {} bytes", received_length);

    let received_version = Message::<Version>::deserialize(&mut buffer, network)?;

    // Check for nonce conflict
    check_nonce_conflict(&version_message, &received_version)?;

    // Compare received version with the current version
    compare_versions(&version_message, &received_version)?;

    // Consume the buffer after processing
    reader.consume(received_length);

    Ok(())
}

fn create_version_message(network: &Network, protocol_version: u32, address: SocketAddr, stream: &TcpStream) -> anyhow::Result<Message<Version>> {
    let version = Version::new(
        protocol_version as i32,
        Services::NODE_NETWORK,
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as i64,
        address,
        stream.local_addr()?,
        rand::random(),
        "".to_string(),
        0,
        false,
    )?;
    Ok(Message::new(network, version))
}

fn check_nonce_conflict(sent_version: &Message<Version>, received_version: &Message<Version>) -> anyhow::Result<()> {
    if sent_version.payload.nonce == received_version.payload.nonce {
        // Err(anyhow::anyhow!("Nonce conflict detected"))
        Err(HandshakeError::NonceConflict)?
    } else {
        Ok(())
    }
}

fn compare_versions(sent_version: &Message<Version>, received_version: &Message<Version>) -> anyhow::Result<()> {
    if sent_version.payload.version > received_version.payload.version {
        tracing::warn!(
            "Received version ({}) is lower than the currently implemented one ({})",
            received_version.payload.version,
            sent_version.payload.version
        );
    }
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
