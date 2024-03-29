pub(crate) mod codec;

use bytecodec::{bytes::BytesEncoder, EncodeExt};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use futures::{SinkExt, StreamExt};
use httpcodec::{BodyEncoder, HttpVersion, ReasonPhrase, RequestEncoder, Response, StatusCode};
use ppaass_crypto::{crypto::RsaCryptoFetcher, random_32_bytes};
use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::{ProxyTcpInitResult, ProxyTcpPayload};
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{PpaassProxyMessage, PpaassProxyMessagePayload};
use tokio::net::TcpStream;

use tokio_util::codec::{Framed, FramedParts};
use tracing::{debug, error};
use url::Url;

use crate::{
    config::AgentConfig, crypto::AgentServerPayloadEncryptionTypeSelector,
    proxy::ProxyConnectionFactory,
};

use crate::{
    error::AgentError,
    transport::{http::codec::HttpCodec, ClientTransportTcpDataRelay},
};

use super::tcp_relay;

const HTTPS_SCHEMA: &str = "https";
const SCHEMA_SEP: &str = "://";
const CONNECT_METHOD: &str = "connect";
const HTTPS_DEFAULT_PORT: u16 = 443;
const HTTP_DEFAULT_PORT: u16 = 80;
const OK_CODE: u16 = 200;
const CONNECTION_ESTABLISHED: &str = "Connection Established";

pub(crate) struct HttpClientTransport<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    client_tcp_stream: TcpStream,
    src_address: PpaassUnifiedAddress,
    initial_buf: BytesMut,
    client_socket_addr: SocketAddr,
    config: Arc<AgentConfig>,
    proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
}

impl<F> HttpClientTransport<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub(crate) fn new(
        client_tcp_stream: TcpStream,
        src_address: PpaassUnifiedAddress,
        initial_buf: BytesMut,
        client_socket_addr: SocketAddr,
        config: Arc<AgentConfig>,
        proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
    ) -> Self {
        Self {
            client_tcp_stream,
            src_address,
            initial_buf,
            client_socket_addr,
            config,
            proxy_connection_factory,
        }
    }

    pub(crate) async fn process(self) -> Result<(), AgentError> {
        let initial_buf = self.initial_buf;
        let src_address = self.src_address;
        let client_tcp_stream = self.client_tcp_stream;
        let client_socket_addr = self.client_socket_addr;
        let mut framed_parts = FramedParts::new(client_tcp_stream, HttpCodec::default());
        framed_parts.read_buf = initial_buf;
        let mut http_framed = Framed::from_parts(framed_parts);
        let http_message = http_framed.next().await.ok_or(AgentError::Other(format!(
            "Nothing to read from client: {client_socket_addr}"
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
                    AgentError::Other(format!(
                        "Fail to encode http data for client [{client_socket_addr}] because of error: {e:?}"
                    ))
                })?
                .into();
            (request_url, Some(encode_result))
        };

        let parsed_request_url = Url::parse(request_url.as_str())
            .map_err(|e| AgentError::Other(format!("Fail to parse url because of error: {e:?}")))?;
        let target_port =
            parsed_request_url
                .port()
                .unwrap_or_else(|| match parsed_request_url.scheme() {
                    HTTPS_SCHEMA => HTTPS_DEFAULT_PORT,
                    _ => HTTP_DEFAULT_PORT,
                });
        let target_host = parsed_request_url
            .host()
            .ok_or(AgentError::Other(format!(
                "Fail to parse target host from request url:{parsed_request_url}"
            )))?
            .to_string();
        if target_host.eq("0.0.0.1") || target_host.eq("127.0.0.1") {
            return Err(AgentError::Other(format!(
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

        let proxy_connection = self
            .proxy_connection_factory
            .create_proxy_connection()
            .await?;
        let (mut proxy_connection_write, mut proxy_connection_read) = proxy_connection.split();
        debug!("Client tcp connection [{src_address}] success to create proxy connection.",);
        proxy_connection_write.send(tcp_init_request).await?;

        let proxy_message = proxy_connection_read
            .next()
            .await
            .ok_or(AgentError::Other(format!(
                "Nothing to read from proxy for client: {client_socket_addr}"
            )))??;

        let PpaassProxyMessage {
            payload: proxy_message_payload,
            ..
        } = proxy_message;

        let PpaassProxyMessagePayload::Tcp(ProxyTcpPayload::Init { result, .. }) =
            proxy_message_payload
        else {
            return Err(AgentError::Other(format!(
                "Not a tcp init response for client {client_socket_addr}."
            )));
        };
        let transport_id = match result {
            ProxyTcpInitResult::Success(transport_id) => transport_id,
            ProxyTcpInitResult::Fail(reason) => {
                error!("Client http tcp connection [{src_address}] fail to initialize tcp connection with proxy because of reason: {reason:?}");
                return Err(AgentError::Other(format!(
                    "Client http tcp connection [{src_address}] fail to initialize tcp connection with proxy because of reason: {reason:?}"
                )));
            }
        };
        debug!("Client http tcp connection [{src_address}] success to initialize tcp connection with proxy on tunnel: {transport_id}");
        if init_data.is_none() {
            //For https proxy
            let http_connect_success_response = Response::new(
                HttpVersion::V1_1,
                StatusCode::new(OK_CODE).unwrap(),
                ReasonPhrase::new(CONNECTION_ESTABLISHED).unwrap(),
                vec![],
            );
            http_framed.send(http_connect_success_response).await?;
        }
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = http_framed.into_parts();
        tcp_relay(
            &self.config,
            ClientTransportTcpDataRelay {
                transport_id,
                client_tcp_stream,
                src_address,
                dst_address,
                proxy_connection_write,
                proxy_connection_read,
                init_data,
                payload_encryption,
            },
        )
        .await
    }
}
