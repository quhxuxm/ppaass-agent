use std::mem::size_of;
use std::sync::{atomic::AtomicU64, Arc};

use bytes::BytesMut;
use futures_util::StreamExt;

use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use tokio_io_timeout::TimeoutStream;
use tracing::{debug, error};

use tokio::sync::mpsc::Sender;
use tokio_tfo::TfoStream;
use tokio_util::codec::{Decoder, Framed, FramedParts};

use crate::{
    config::AgentServerConfig,
    error::AgentServerError,
    event::AgentServerEvent,
    proxy::ProxyConnectionFactory,
    publish_server_event,
    tunnel::{bo::TunnelCreateRequest, http::HttpTunnel, socks::Socks5Tunnel},
    SOCKS_V4, SOCKS_V5,
};

pub(crate) enum Tunnel<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    Socks5(Socks5Tunnel<F>),
    Http(HttpTunnel<F>),
}

pub(crate) enum ClientProtocol {
    /// The client side choose to use HTTP proxy
    Http,
    /// The client side choose to use Socks5 proxy
    Socks5,
    /// The client side choose to use Socks4 proxy
    Socks4,
}

pub(crate) struct SwitchClientProtocolDecoder;

impl Decoder for SwitchClientProtocolDecoder {
    type Item = ClientProtocol;

    type Error = AgentServerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Use the first byte to decide what protocol the client side is using.
        if src.len() < size_of::<u8>() {
            return Ok(None);
        }
        let protocol_flag = src[0];
        match protocol_flag {
            SOCKS_V5 => Ok(Some(ClientProtocol::Socks5)),
            SOCKS_V4 => Ok(Some(ClientProtocol::Socks4)),
            _ => Ok(Some(ClientProtocol::Http)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ClientDispatcher<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    config: Arc<AgentServerConfig>,
    proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
}

impl<F> ClientDispatcher<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub(crate) fn new(
        config: Arc<AgentServerConfig>,
        proxy_connection_factory: ProxyConnectionFactory<F>,
    ) -> Self {
        Self {
            config,
            proxy_connection_factory: Arc::new(proxy_connection_factory),
        }
    }

    pub(crate) async fn dispatch(
        &self,
        client_tcp_stream: TimeoutStream<TfoStream>,
        client_socket_address: &PpaassUnifiedAddress,
        server_event_tx: &Sender<AgentServerEvent>,
        upload_bytes_amount: Arc<AtomicU64>,
        download_bytes_amount: Arc<AtomicU64>,
    ) -> Result<Tunnel<F>, AgentServerError> {
        let mut client_message_framed = Framed::with_capacity(
            Box::pin(client_tcp_stream),
            SwitchClientProtocolDecoder,
            self.config.client_receive_buffer_size(),
        );
        let client_protocol = match client_message_framed.next().await {
            Some(Ok(client_protocol)) => client_protocol,
            Some(Err(e)) => {
                error!("Fail to create tunnel for client connection [{client_socket_address}] because of error happen when parse client protocol: {e:?}");
                publish_server_event(
                    server_event_tx,
                    AgentServerEvent::TunnelInitializeFail {
                        client_socket_address: client_socket_address.clone(),
                        src_address: None,
                        dst_address: None,
                        reason: format!(
                            "Fail to create tunnel for client connection [{client_socket_address}]  because of error happen when parse client protocol."
                        ),
                    },
                )
                .await;
                return Err(e);
            }
            None => {
                error!("Fail to create tunnel for client connection [{client_socket_address}] because of nothing read from client.");
                publish_server_event(
                    server_event_tx,
                    AgentServerEvent::TunnelInitializeFail {
                        client_socket_address: client_socket_address.clone(),
                        src_address: None,
                        dst_address: None,
                        reason: format!(
                            "Fail to create tunnel for client connection [{client_socket_address}] because of nothing read from client."
                        ),
                    },
                )
                .await;
                return Err(AgentServerError::Other(format!("Fail to create tunnel for client connection [{client_socket_address}] because of nothing read from client.")));
            }
        };

        let create_tunnel_request = TunnelCreateRequest {
            src_address: client_socket_address.clone(),
            client_socket_address: client_socket_address.clone(),
            config: self.config.clone(),
            proxy_connection_factory: self.proxy_connection_factory.clone(),
            upload_bytes_amount,
            download_bytes_amount,
        };

        match client_protocol {
            ClientProtocol::Socks5 => {
                // For socks5 protocol
                let FramedParts {
                    io: client_tcp_stream,
                    read_buf: initial_buf,
                    ..
                } = client_message_framed.into_parts();
                debug!(
                    "Client tcp connection [{client_socket_address}] begin to serve socks 5 protocol"
                );
                Ok(Tunnel::Socks5(Socks5Tunnel::new(
                    create_tunnel_request,
                    client_tcp_stream,
                    initial_buf,
                )))
            }

            ClientProtocol::Socks4 => {
                // For socks4 protocol
                error!("Fail to create tunnel for client connection [{client_socket_address}] because of socks4 not support.");
                publish_server_event(
                    server_event_tx,
                    AgentServerEvent::TunnelInitializeFail {
                        client_socket_address:client_socket_address.clone(),
                        src_address: None,
                        dst_address: None,
                        reason: format!("Fail to create tunnel for client connection [{client_socket_address}] because of socks4 not support."),
                    },
                )
                .await;
                Err(AgentServerError::Other(format!("Fail to create tunnel for client connection [{client_socket_address}] because of socks4 not support."
                )))
            }
            ClientProtocol::Http => {
                // For http protocol
                let FramedParts {
                    io: client_tcp_stream,
                    read_buf: initial_buf,
                    ..
                } = client_message_framed.into_parts();
                debug!(
                    "Client tcp connection [{client_socket_address}] begin to serve http protocol"
                );
                Ok(Tunnel::Http(HttpTunnel::new(
                    create_tunnel_request,
                    client_tcp_stream,
                    initial_buf,
                )))
            }
        }
    }
}
