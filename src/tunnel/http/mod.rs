pub(crate) mod codec;
use bytecodec::{bytes::BytesEncoder, EncodeExt};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, AtomicU64},
    Arc,
};
use tokio_io_timeout::TimeoutStream;

use bytes::{Bytes, BytesMut};

use futures::{SinkExt, StreamExt};
use httpcodec::{BodyEncoder, HttpVersion, ReasonPhrase, RequestEncoder, Response, StatusCode};
use ppaass_crypto::{crypto::RsaCryptoFetcher, random_32_bytes};
use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::{ProxyTcpInitResult, ProxyTcpPayload};
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{PpaassProxyMessage, PpaassProxyMessagePayload};
use tokio::sync::mpsc::Sender;
use tokio_tfo::TfoStream;
use tokio_util::codec::{Framed, FramedParts};
use tracing::{debug, error};
use url::Url;

use crate::{
    config::AgentServerConfig, crypto::AgentServerPayloadEncryptionTypeSelector,
    proxy::ProxyConnectionFactory, publish_server_event,
};

use crate::event::AgentServerEvent;
use crate::{
    error::AgentServerError,
    tunnel::{http::codec::HttpCodec, TunnelTcpDataRelay},
};

use super::{bo::TunnelCreateRequest, tcp_relay};

const HTTPS_SCHEMA: &str = "https";
const SCHEMA_SEP: &str = "://";
const CONNECT_METHOD: &str = "connect";
const HTTPS_DEFAULT_PORT: u16 = 443;
const HTTP_DEFAULT_PORT: u16 = 80;
const OK_CODE: u16 = 200;
const CONNECTION_ESTABLISHED: &str = "Connection Established";

pub(crate) struct HttpTunnel<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    client_tcp_stream: Pin<Box<TimeoutStream<TfoStream>>>,
    src_address: PpaassUnifiedAddress,
    initial_buf: BytesMut,
    client_socket_address: PpaassUnifiedAddress,
    config: Arc<AgentServerConfig>,
    proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
    upload_bytes_amount: Arc<AtomicU64>,
    download_bytes_amount: Arc<AtomicU64>,
}

impl<F> HttpTunnel<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub(crate) fn new(
        request: TunnelCreateRequest<F>,
        client_tcp_stream: Pin<Box<TimeoutStream<TfoStream>>>,
        initial_buf: BytesMut,
    ) -> Self {
        Self {
            client_tcp_stream,
            src_address: request.src_address,
            initial_buf,
            client_socket_address: request.client_socket_address,
            config: request.config,
            proxy_connection_factory: request.proxy_connection_factory,
            upload_bytes_amount: request.upload_bytes_amount,
            download_bytes_amount: request.download_bytes_amount,
        }
    }

    pub(crate) async fn process(
        self,
        server_event_tx: &Sender<AgentServerEvent>,
        stopped_status: Arc<AtomicBool>,
    ) -> Result<(), AgentServerError> {
        let upload_bytes_amount = self.upload_bytes_amount;
        let download_bytes_amount = self.download_bytes_amount;
        let initial_buf = self.initial_buf;
        let client_socket_address = self.client_socket_address;
        let src_address = self.src_address;
        let client_tcp_stream = self.client_tcp_stream;

        let mut framed_parts = FramedParts::new(client_tcp_stream, HttpCodec::default());
        framed_parts.read_buf = initial_buf;
        let mut http_framed = Framed::from_parts(framed_parts);
        let http_message = http_framed
            .next()
            .await
            .ok_or(AgentServerError::Other(format!(
                "Nothing to read from client: {client_socket_address}"
            )))??;
        let http_method = http_message.method().to_string().to_lowercase();
        let (request_url, init_data) = if http_method == CONNECT_METHOD {
            (
                format!(
                    "{}{}{}",
                    HTTPS_SCHEMA,
                    SCHEMA_SEP,
                    http_message.request_target()
                ),
                None,
            )
        } else {
            let request_url = http_message.request_target().to_string();
            let mut http_data_encoder = RequestEncoder::<BodyEncoder<BytesEncoder>>::default();
            let encode_result: Bytes = http_data_encoder
                .encode_into_bytes(http_message)
                .map_err(|e| {
                    AgentServerError::Other(format!(
                        "Fail to encode http data for client [{client_socket_address}] because of error: {e:?}"
                    ))
                })?
                .into();
            (request_url, Some(encode_result))
        };

        let parsed_request_url = Url::parse(request_url.as_str()).map_err(|e| {
            AgentServerError::Other(format!("Fail to parse url because of error: {e:?}"))
        })?;
        let target_port =
            parsed_request_url
                .port()
                .unwrap_or_else(|| match parsed_request_url.scheme() {
                    HTTPS_SCHEMA => HTTPS_DEFAULT_PORT,
                    _ => HTTP_DEFAULT_PORT,
                });
        let target_host = parsed_request_url
            .host()
            .ok_or(AgentServerError::Other(format!(
                "Fail to parse target host from request url:{parsed_request_url}"
            )))?
            .to_string();
        if target_host.eq("0.0.0.1") || target_host.eq("127.0.0.1") {
            return Err(AgentServerError::Other(format!(
                "0.0.0.1 or 127.0.0.1 is not a valid destination address: {target_host}"
            )));
        }
        let dst_address = PpaassUnifiedAddress::Domain {
            host: target_host,
            port: target_port,
        };

        let user_token = self.config.user_token();
        let payload_encryption =
            AgentServerPayloadEncryptionTypeSelector::select(user_token, Some(random_32_bytes()));
        let tcp_init_request = PpaassMessageGenerator::generate_agent_tcp_init_message(
            user_token.to_string(),
            src_address.clone(),
            dst_address.clone(),
            payload_encryption.clone(),
        )?;

        let proxy_connection = match self
            .proxy_connection_factory
            .create_proxy_connection()
            .await
        {
            Ok(proxy_connection) => proxy_connection,
            Err(e) => {
                error!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of error: {e:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!(
                        "Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail."
                    ),
                }).await;

                return Err(e);
            }
        };

        let (mut proxy_connection_write, mut proxy_connection_read) = proxy_connection.split();
        debug!("Client tcp connection [{src_address}] success to create proxy connection.",);
        if let Err(e) = proxy_connection_write.send(tcp_init_request).await {
            error!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of error when create proxy connection: {e:?}");
            publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                client_socket_address: client_socket_address.clone(),
                dst_address: Some(dst_address.clone()),
                src_address: Some(src_address.clone()),
                reason: format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of error when create proxy connection."),
            }).await;
            return Err(e);
        };

        let proxy_message = match proxy_connection_read.next().await {
            Some(Ok(proxy_message)) => proxy_message,
            Some(Err(e)) => {
                error!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of error return init message from proxy connection: {e:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address: client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of error return init message from proxy connection."),
                }).await;
                return Err(e);
            }
            None => {
                error!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of nothing return from proxy connection.");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of nothing return from proxy connection."),
                }).await;
                return  Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of nothing return from proxy connection.")));
            }
        };

        let PpaassProxyMessage {
            payload: proxy_message_payload,
            ..
        } = proxy_message;

        let PpaassProxyMessagePayload::Tcp(ProxyTcpPayload::Init { result, .. }) =
            proxy_message_payload
        else {
            error!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of did not receive init result from proxy connection.");
            publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of did not receive init result from proxy connection."),
                }).await;
            return  Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of did not receive init result from proxy connection.")));
        };
        let tunnel_id = match result {
            ProxyTcpInitResult::Success(tunnel_id) => tunnel_id,
            ProxyTcpInitResult::Fail(reason) => {
                error!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of reason: {reason:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of reason: {reason:?}")
                }).await;
                return Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of reason: {reason:?}")));
            }
        };
        debug!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] success with id: {tunnel_id}");

        if init_data.is_none() {
            //For https proxy
            let http_connect_success_response = Response::new(
                HttpVersion::V1_1,
                StatusCode::new(OK_CODE).unwrap(),
                ReasonPhrase::new(CONNECTION_ESTABLISHED).unwrap(),
                vec![],
            );
            if let Err(e) = http_framed.send(http_connect_success_response).await {
                error!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of error when write OK to client: {e:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address: client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] to [{dst_address}] fail because of error when write OK to client.")
                }).await;
                return Err(e);
            };
        }
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = http_framed.into_parts();

        publish_server_event(
            server_event_tx,
            AgentServerEvent::TunnelInitializeSuccess {
                client_socket_address: client_socket_address.clone(),
                dst_address: Some(dst_address.clone()),
                src_address: Some(src_address.clone()),
            },
        )
        .await;
        tcp_relay(
            &self.config,
            TunnelTcpDataRelay {
                tunnel_id,
                client_tcp_stream,
                client_socket_address,
                src_address,
                dst_address,
                proxy_connection_write,
                proxy_connection_read,
                init_data,
                payload_encryption,
                upload_bytes_amount,
                download_bytes_amount,
                stopped_status,
            },
            server_event_tx,
        )
        .await
    }
}
