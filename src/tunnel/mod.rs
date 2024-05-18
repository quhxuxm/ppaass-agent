pub(crate) mod bo;
pub(crate) mod dispatcher;
mod http;
mod socks;

use std::sync::{
    atomic::{AtomicBool, AtomicU64},
    Arc,
};
use std::{sync::atomic::Ordering, time::Duration};

use crate::{config::AgentServerConfig, error::AgentServerError, publish_server_event};

use bytes::{Bytes, BytesMut};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};

use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::ProxyTcpPayload;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryption;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassProxyMessage, PpaassProxyMessagePayload};
use std::pin::Pin;
use tracing::{debug, error};

use crate::codec::PpaassProxyEdgeCodec;

use crate::event::AgentServerEvent;
use tokio::sync::mpsc::Sender;
use tokio_io_timeout::TimeoutStream;
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_tfo::TfoStream;
use tokio_util::codec::{BytesCodec, Framed};

struct TunnelTcpDataRelay<F>
where
    F: RsaCryptoFetcher,
{
    tunnel_id: String,
    client_tcp_stream: Pin<Box<TimeoutStream<TfoStream>>>,
    client_socket_address: PpaassUnifiedAddress,
    src_address: PpaassUnifiedAddress,
    dst_address: PpaassUnifiedAddress,
    proxy_connection_write:
        SplitSink<Framed<TimeoutStream<TfoStream>, PpaassProxyEdgeCodec<F>>, PpaassAgentMessage>,
    proxy_connection_read: SplitStream<Framed<TimeoutStream<TfoStream>, PpaassProxyEdgeCodec<F>>>,
    init_data: Option<Bytes>,
    payload_encryption: PpaassMessagePayloadEncryption,
    upload_bytes_amount: Arc<AtomicU64>,
    download_bytes_amount: Arc<AtomicU64>,
    stopped_status: Arc<AtomicBool>,
}

async fn tcp_relay<F>(
    config: &AgentServerConfig,
    tcp_relay_info: TunnelTcpDataRelay<F>,
    server_event_tx: &Sender<AgentServerEvent>,
) -> Result<(), AgentServerError>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    let user_token = config.user_token().to_string();
    let TunnelTcpDataRelay {
        tunnel_id,
        client_tcp_stream,
        client_socket_address,
        src_address,
        dst_address,
        mut proxy_connection_write,
        proxy_connection_read,
        init_data,
        payload_encryption,
        upload_bytes_amount,
        download_bytes_amount,
        stopped_status,
    } = tcp_relay_info;
    debug!(
        "Agent going to relay tcp data from source: {src_address} to destination: {dst_address}"
    );
    publish_server_event(
        server_event_tx,
        AgentServerEvent::TunnelStartRelay {
            client_socket_address: client_socket_address.clone(),
            src_address: Some(src_address.clone()),
            dst_address: Some(dst_address.clone()),
        },
    )
    .await;
    let mut client_tcp_stream = TimeoutStream::new(client_tcp_stream);
    client_tcp_stream.set_read_timeout(Some(Duration::from_secs(
        config.client_connection_read_timeout(),
    )));
    client_tcp_stream.set_write_timeout(Some(Duration::from_secs(
        config.client_connection_write_timeout(),
    )));
    let client_io_framed = Framed::with_capacity(
        client_tcp_stream,
        BytesCodec::new(),
        config.client_receive_buffer_size(),
    );
    let (mut client_io_write, client_io_read) = client_io_framed.split::<BytesMut>();

    if let Some(init_data) = init_data {
        let agent_message = PpaassMessageGenerator::generate_agent_tcp_data_message(
            user_token.clone(),
            payload_encryption.clone(),
            init_data,
        )?;
        proxy_connection_write.send(agent_message).await?;
    }

    {
        let tunnel_id = tunnel_id.clone();
        let dst_address = dst_address.clone();
        let stopped_status = stopped_status.clone();
        tokio::spawn(async move {
            // Forward client data to proxy
            let client_io_read = TokioStreamExt::fuse(client_io_read);
            if let Err(e) = TokioStreamExt::map_while(client_io_read, |client_message| {
                if stopped_status.load(Ordering::Relaxed) {
                    return None;
                }
                let client_message = client_message.ok()?;
                let message_size = client_message.len() as u64;
                let tcp_data = PpaassMessageGenerator::generate_agent_tcp_data_message(
                    user_token.to_string(),
                    payload_encryption.clone(),
                    client_message.freeze(),
                )
                .ok()?;
                upload_bytes_amount.fetch_add(message_size, Ordering::Relaxed);
                Some(Ok(tcp_data))
            })
            .forward(&mut proxy_connection_write)
            .await
            {
                error!("Transport [{tunnel_id}] error happen when relay tcp data from client to proxy for destination [{dst_address}], error: {e:?}");
            }
            if let Err(e) = proxy_connection_write.close().await {
                error!(
                    "Transport [{tunnel_id}] fail to close proxy connection because of error: {e:?}"
                );
            };
        });
    }

    tokio::spawn(async move {
        let proxy_connection_read = TokioStreamExt::fuse(proxy_connection_read);
        if let Err(e) = TokioStreamExt::map_while(proxy_connection_read, |proxy_message| {
            if stopped_status.load(Ordering::Relaxed) {
                return None;
            }
            let proxy_message = proxy_message.ok()?;
            let PpaassProxyMessage {
                payload: PpaassProxyMessagePayload::Tcp(ProxyTcpPayload::Data { content }),
                ..
            } = proxy_message
            else {
                error!("Fail to parse proxy message payload because of not a tcp data");
                return None;
            };
            let download_message_len = content.len() as u64;
            download_bytes_amount.fetch_add(download_message_len, Ordering::Relaxed);
            Some(Ok(BytesMut::from_iter(content)))
        })
        .forward(&mut client_io_write)
        .await
        {
            error!("Transport [{tunnel_id}] error happen when relay tcp data from proxy to client for destination [{dst_address}], error: {e:?}",);
        }
        if let Err(e) = client_io_write.close().await {
            error!(
                "Transport [{tunnel_id}] fail to close client connection beccause of error: {e:?}"
            );
        };
    });

    Ok(())
}
