mod codec;
mod message;

use std::pin::Pin;
use std::sync::{atomic::AtomicU64, Arc};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::atomic::AtomicBool,
};

use bytes::{Bytes, BytesMut};

use futures::{SinkExt, StreamExt};

use ppaass_crypto::{crypto::RsaCryptoFetcher, random_32_bytes};
use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::{ProxyTcpInitResult, ProxyTcpPayload};
use ppaass_protocol::message::payload::udp::ProxyUdpPayload;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{PpaassProxyMessage, PpaassProxyMessagePayload};

use tokio_io_timeout::TimeoutStream;
use tracing::{debug, error, info};

use tokio::sync::mpsc::Sender;
use tokio::{io::AsyncReadExt, net::UdpSocket};
use tokio_tfo::TfoStream;
use tokio_util::codec::{Framed, FramedParts};

use self::message::{Socks5InitCommandResultStatus, Socks5UdpDataPacket};

use crate::{
    config::AgentServerConfig, crypto::AgentServerPayloadEncryptionTypeSelector,
    proxy::ProxyConnectionFactory, publish_server_event,
};

use crate::event::AgentServerEvent;
use crate::{
    error::AgentServerError,
    tunnel::{
        socks::{
            codec::{Socks5AuthCommandContentCodec, Socks5InitCommandContentCodec},
            message::{
                Socks5AuthCommandResult, Socks5AuthMethod, Socks5InitCommandResult,
                Socks5InitCommandType,
            },
        },
        TunnelTcpDataRelay,
    },
};

use super::{bo::TunnelCreateRequest, tcp_relay};

struct Socks5HandleConnectCommandRequest<'config, 'proxyfactory, F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub config: &'config AgentServerConfig,
    pub proxy_connection_factory: &'proxyfactory ProxyConnectionFactory<F>,
    pub src_address: PpaassUnifiedAddress,
    pub dst_address: PpaassUnifiedAddress,
    pub client_socket_address: PpaassUnifiedAddress,
    pub socks5_init_framed:
        Framed<Pin<Box<TimeoutStream<TfoStream>>>, Socks5InitCommandContentCodec>,
    pub upload_bytes_amount: Arc<AtomicU64>,
    pub download_bytes_amount: Arc<AtomicU64>,
    pub stopped_status: Arc<AtomicBool>,
}

pub(crate) struct Socks5Tunnel<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    config: Arc<AgentServerConfig>,
    client_tcp_stream: Pin<Box<TimeoutStream<TfoStream>>>,
    src_address: PpaassUnifiedAddress,
    initial_buf: BytesMut,
    client_socket_address: PpaassUnifiedAddress,
    proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
    upload_bytes_amount: Arc<AtomicU64>,
    download_bytes_amount: Arc<AtomicU64>,
}

impl<F> Socks5Tunnel<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub(crate) fn new(
        create_request: TunnelCreateRequest<F>,
        client_tcp_stream: Pin<Box<TimeoutStream<TfoStream>>>,
        initial_buf: BytesMut,
    ) -> Self {
        Self {
            config: create_request.config,
            client_tcp_stream,
            src_address: create_request.src_address,
            initial_buf,
            client_socket_address: create_request.client_socket_address,
            proxy_connection_factory: create_request.proxy_connection_factory,
            upload_bytes_amount: create_request.upload_bytes_amount,
            download_bytes_amount: create_request.download_bytes_amount,
        }
    }

    pub(crate) async fn process(
        self,
        server_event_tx: &Sender<AgentServerEvent>,
        stopped_status: Arc<AtomicBool>,
    ) -> Result<(), AgentServerError> {
        let initial_buf = self.initial_buf;
        let src_address = self.src_address;
        let client_tcp_stream = self.client_tcp_stream;
        let client_socket_address = self.client_socket_address;

        let mut client_auth_framed_parts =
            FramedParts::new(client_tcp_stream, Socks5AuthCommandContentCodec);
        client_auth_framed_parts.read_buf = initial_buf;
        let mut client_auth_framed = Framed::from_parts(client_auth_framed_parts);
        let client_auth_command = match client_auth_framed.next().await {
            Some(Ok(client_auth_command)) => client_auth_command,
            Some(Err(e)) => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] fail because of error: {e:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: None,
                    src_address: Some(src_address.clone()),
                    reason: format!(
                        "Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] fail."
                    ),
                }).await;
                return Err(e);
            }
            None => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] fail because of nothing from client.");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: None,
                    src_address: Some(src_address.clone()),
                    reason: format!(
                        "Client connection [{client_socket_address}] initialize http tunnel from [{src_address}] fail."
                    ),
                }).await;
                return Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] fail because of nothing from client.")));
            }
        };

        debug!(
            "Client tcp connection [{src_address}] start socks5 authenticate process, authenticate methods in request: {:?}",
            client_auth_command.methods
        );
        let client_auth_response =
            Socks5AuthCommandResult::new(Socks5AuthMethod::NoAuthenticationRequired);
        if let Err(e) = client_auth_framed.send(client_auth_response).await {
            error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] fail because of error happen when send auth command response to client: {e:?}");
            publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                client_socket_address:client_socket_address.clone(),
                dst_address: None,
                src_address: Some(src_address.clone()),
                reason: format!(
                    "Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] fail because of error happen when send auth command response to client: {e:?}"
                ),
            }).await;
            return Err(e);
        };

        let FramedParts {
            io: client_tcp_stream,
            ..
        } = client_auth_framed.into_parts();

        let mut socks5_init_framed = Framed::new(client_tcp_stream, Socks5InitCommandContentCodec);
        let socks5_init_command = match socks5_init_framed.next().await {
            Some(Ok(socks5_init_command)) => socks5_init_command,
            Some(Err(e)) => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel fail because of error happen when read init command from client: {e:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                client_socket_address:client_socket_address.clone(),
                dst_address: None,
                src_address: Some(src_address.clone()),
                reason: format!(
                    "Client connection [{client_socket_address}] initialize socks5 tunnel fail because of error happen when read init command from client."
                ),
            }).await;
                return Err(e);
            }
            None => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel fail because of nothing from client when read init command.");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                client_socket_address:client_socket_address.clone(),
                dst_address: None,
                src_address: Some(src_address.clone()),
                reason: format!(
                    "Client connection [{client_socket_address}] initialize socks5 tunnel fail because of nothing from client when read init command."
                ),
            }).await;
                return Err(AgentServerError::Other(format!(
                    "Client connection [{client_socket_address}] initialize socks5 tunnel fail because of nothing from client when read init command."
                )));
            }
        };
        debug!(
            "Client tcp connection [{src_address}] start socks5 init process, command type: {:?}, destination address: {:?}",
            socks5_init_command.request_type, socks5_init_command.dst_address
        );

        match socks5_init_command.request_type {
            Socks5InitCommandType::Bind => {
                Self::handle_bind_command(
                    src_address,
                    socks5_init_command.dst_address.into(),
                    socks5_init_framed,
                )
                .await
            }
            Socks5InitCommandType::UdpAssociate => {
                Self::handle_udp_associate_command(
                    &self.config,
                    &self.proxy_connection_factory,
                    socks5_init_command.dst_address.into(),
                    socks5_init_framed,
                )
                .await
            }
            Socks5InitCommandType::Connect => {
                Self::handle_connect_command(
                    Socks5HandleConnectCommandRequest {
                        config: &self.config,
                        proxy_connection_factory: &self.proxy_connection_factory,
                        src_address,
                        dst_address: socks5_init_command.dst_address.into(),
                        client_socket_address,
                        socks5_init_framed,
                        upload_bytes_amount: self.upload_bytes_amount,
                        download_bytes_amount: self.download_bytes_amount,
                        stopped_status,
                    },
                    server_event_tx,
                )
                .await
            }
        }
    }

    async fn start_udp_relay(
        config: &AgentServerConfig,
        proxy_connection_factory: &ProxyConnectionFactory<F>,
        client_tcp_stream: Pin<Box<TimeoutStream<TfoStream>>>,
        agent_udp_bind_socket: UdpSocket,
        client_udp_restrict_address: PpaassUnifiedAddress,
    ) -> Result<(), AgentServerError> {
        debug!("Agent begin to relay udp packet for client: {client_udp_restrict_address:?}");
        tokio::select! {
            udp_relay_tcp_check_result = Self::check_udp_relay_tcp_connection(client_tcp_stream)=>{
                Ok(udp_relay_tcp_check_result?)
            },
            udp_relay_result = Self::relay_udp_data(config,proxy_connection_factory,client_udp_restrict_address,agent_udp_bind_socket)=>{
                Ok(udp_relay_result?)
            }
        }
    }

    async fn check_udp_relay_tcp_connection(
        mut client_tcp_stream: Pin<Box<TimeoutStream<TfoStream>>>,
    ) -> Result<(), AgentServerError> {
        loop {
            let mut client_data_buf = [0u8; 1];
            let size = client_tcp_stream.read(&mut client_data_buf).await?;
            if size == 0 {
                info!("Client udp associate tcp stream closed.");
                return Ok(());
            }
        }
    }

    async fn relay_udp_data(
        config: &AgentServerConfig,
        proxy_connection_factory: &ProxyConnectionFactory<F>,
        client_udp_restrict_address: PpaassUnifiedAddress,
        agent_udp_bind_socket: UdpSocket,
    ) -> Result<(), AgentServerError> {
        let user_token = config.user_token();
        let payload_encryption =
            AgentServerPayloadEncryptionTypeSelector::select(user_token, Some(random_32_bytes()));
        loop {
            let mut client_udp_buf = [0u8; 65535];
            let (len, client_udp_address) =
                agent_udp_bind_socket.recv_from(&mut client_udp_buf).await?;
            let src_address: PpaassUnifiedAddress = client_udp_address.into();
            if client_udp_restrict_address != src_address {
                error!("The udp packet sent from client not valid, client udp restrict address: {client_udp_restrict_address}, src address: {src_address}");
                continue;
            }
            let client_udp_buf = client_udp_buf[..len].to_vec();
            let client_udp_bytes = Bytes::from_iter(client_udp_buf);
            let client_to_dst_socks5_udp_packet: Socks5UdpDataPacket =
                client_udp_bytes.try_into()?;
            let dst_address: PpaassUnifiedAddress = client_to_dst_socks5_udp_packet.address.into();
            let agent_udp_message = PpaassMessageGenerator::generate_agent_udp_data_message(
                user_token.to_string(),
                payload_encryption.clone(),
                client_udp_restrict_address.clone(),
                dst_address.clone(),
                client_to_dst_socks5_udp_packet.data,
            )?;
            let proxy_connection = proxy_connection_factory.create_proxy_connection().await?;
            let (mut proxy_connection_write, mut proxy_connection_read) = proxy_connection.split();
            proxy_connection_write.send(agent_udp_message).await?;
            let proxy_udp_message = match proxy_connection_read.next().await {
                Some(Ok(proxy_udp_message)) => proxy_udp_message,
                Some(Err(e)) => return Err(e),
                None => return Ok(()),
            };
            let PpaassProxyMessage {
                payload: proxy_message_payload,
                ..
            } = proxy_udp_message;
            let PpaassProxyMessagePayload::Udp(ProxyUdpPayload {
                src_address,
                dst_address,
                data,
            }) = proxy_message_payload
            else {
                return Err(AgentServerError::Other(
                    "Not a udp data from proxy.".to_string(),
                ));
            };
            debug!("Udp packet send from agent to client, dst_address: {dst_address}, src_address: {src_address}");
            let agent_to_client_socks5_udp_packet = Socks5UdpDataPacket {
                frag: 0,
                address: dst_address.clone().try_into()?,
                data,
            };
            let agent_socks5_udp_packet_bytes: Bytes = agent_to_client_socks5_udp_packet.into();
            let src_socket_address = src_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
            agent_udp_bind_socket
                .send_to(&agent_socks5_udp_packet_bytes, &src_socket_address[..])
                .await?;
        }
    }

    #[allow(unused)]
    async fn handle_bind_command(
        src_address: PpaassUnifiedAddress,
        dst_address: PpaassUnifiedAddress,
        mut socks5_init_framed: Framed<
            Pin<Box<TimeoutStream<TfoStream>>>,
            Socks5InitCommandContentCodec,
        >,
    ) -> Result<(), AgentServerError> {
        unimplemented!("Still not implement the socks5 bind command")
    }

    async fn handle_udp_associate_command(
        config: &AgentServerConfig,
        proxy_connection_factory: &ProxyConnectionFactory<F>,
        client_udp_restrict_address: PpaassUnifiedAddress,
        mut socks5_init_framed: Framed<
            Pin<Box<TimeoutStream<TfoStream>>>,
            Socks5InitCommandContentCodec,
        >,
    ) -> Result<(), AgentServerError> {
        debug!(
            "Client do socks5 udp associate on restrict address: {client_udp_restrict_address:?}"
        );
        let agent_udp_bind_socket = UdpSocket::bind("0.0.0.0:0").await?;
        debug!("Agent bind udp socket: {agent_udp_bind_socket:?}");
        let socks5_init_success_result = Socks5InitCommandResult::new(
            Socks5InitCommandResultStatus::Succeeded,
            Some(agent_udp_bind_socket.local_addr()?.into()),
        );
        socks5_init_framed.send(socks5_init_success_result).await?;
        debug!("Agent send socks5 udp associate response to client: {agent_udp_bind_socket:?}");
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = socks5_init_framed.into_parts();

        Self::start_udp_relay(
            config,
            proxy_connection_factory,
            client_tcp_stream,
            agent_udp_bind_socket,
            client_udp_restrict_address,
        )
        .await?;
        Ok(())
    }

    async fn handle_connect_command(
        request: Socks5HandleConnectCommandRequest<'_, '_, F>,
        server_event_tx: &Sender<AgentServerEvent>,
    ) -> Result<(), AgentServerError> {
        let Socks5HandleConnectCommandRequest {
            config,
            proxy_connection_factory,
            src_address,
            dst_address,
            client_socket_address,
            mut socks5_init_framed,
            upload_bytes_amount,
            download_bytes_amount,
            stopped_status,
        } = request;
        match &dst_address {
            PpaassUnifiedAddress::Ip(socket_addr) => {
                if socket_addr.ip().is_multicast() {
                    publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail { client_socket_address:client_socket_address.clone(), src_address: Some(src_address.clone()), dst_address: Some(dst_address.clone()), reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of destination address is multicast.") }).await;
                    return Err(AgentServerError::Other(format!(
                        "Multicast address is not allowed: {socket_addr}"
                    )));
                }
                if socket_addr.ip().is_loopback() {
                    publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail { client_socket_address:client_socket_address.clone(), src_address: Some(src_address.clone()), dst_address: Some(dst_address.clone()), reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of destination address is loopback.") }).await;
                    return Err(AgentServerError::Other(format!(
                        "Loopback address is not allowed: {socket_addr}"
                    )));
                }
                if socket_addr.ip().is_unspecified() {
                    publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail { client_socket_address:client_socket_address.clone(), src_address: Some(src_address.clone()), dst_address: Some(dst_address.clone()), reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of destination address is unspecified.") }).await;
                    return Err(AgentServerError::Other(format!(
                        "Unspecified address is not allowed: {socket_addr}"
                    )));
                }
                if let SocketAddr::V4(ipv4_addr) = socket_addr {
                    if ipv4_addr.ip().is_broadcast() {
                        publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail { client_socket_address:client_socket_address.clone(), src_address: Some(src_address.clone()), dst_address: Some(dst_address.clone()), reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of destination address is broadcast.") }).await;
                        return Err(AgentServerError::Other(format!(
                            "Broadcast address is not allowed: {socket_addr}"
                        )));
                    }
                    if ipv4_addr.ip().is_private() {
                        publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail { client_socket_address:client_socket_address.clone(), src_address: Some(src_address.clone()), dst_address: Some(dst_address.clone()), reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of destination address is private.") }).await;
                        return Err(AgentServerError::Other(format!(
                            "Private address is not allowed: {socket_addr}"
                        )));
                    }
                    if ipv4_addr.ip().is_link_local() {
                        publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail { client_socket_address:client_socket_address.clone(), src_address: Some(src_address.clone()), dst_address: Some(dst_address.clone()), reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of destination address is local.") }).await;
                        return Err(AgentServerError::Other(format!(
                            "Link local address is not allowed: {socket_addr}"
                        )));
                    }
                }
            }
            PpaassUnifiedAddress::Domain { host, port } => {
                if host.eq("0.0.0.1") || host.eq("127.0.0.1") || host.eq("localhost") {
                    publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail { client_socket_address:client_socket_address.clone(), src_address: Some(src_address.clone()), dst_address: Some(dst_address.clone()), reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of destination address is local address.") }).await;
                    return Err(AgentServerError::Other(format!(
                        "0.0.0.1, 127.0.0.1 or localhost is not a valid destination address: {host}:{port}"
                    )));
                }
            }
        };

        let user_token = config.user_token();
        let payload_encryption =
            AgentServerPayloadEncryptionTypeSelector::select(user_token, Some(random_32_bytes()));
        let tcp_init_request = PpaassMessageGenerator::generate_agent_tcp_init_message(
            user_token.to_string(),
            src_address.clone(),
            dst_address.clone(),
            payload_encryption.clone(),
        )?;
        let proxy_connection = match proxy_connection_factory.create_proxy_connection().await {
            Ok(proxy_connection) => proxy_connection,
            Err(e) => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error happen when create proxy connection: {e:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!(
                        "Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error happen when create proxy connection."
                    ),
                }).await;

                return Err(e);
            }
        };
        publish_server_event(
            server_event_tx,
            AgentServerEvent::TunnelInitializeSuccess {
                client_socket_address: client_socket_address.clone(),
                dst_address: Some(dst_address.clone()),
                src_address: Some(src_address.clone()),
            },
        )
        .await;
        let (mut proxy_connection_write, mut proxy_connection_read) = proxy_connection.split();
        debug!("Client tcp connection [{src_address}] success create proxy connection.",);
        if let Err(e) = proxy_connection_write.send(tcp_init_request).await {
            error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error when create proxy connection: {e:?}");
            publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                client_socket_address: client_socket_address.clone(),
                dst_address: Some(dst_address.clone()),
                src_address: Some(src_address.clone()),
                reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error when create proxy connection."),
            }).await;
            return Err(e);
        };

        let proxy_message = match proxy_connection_read.next().await {
            Some(Ok(proxy_message)) => proxy_message,
            Some(Err(e)) => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error return init message from proxy connection: {e:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address: client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error return init message from proxy connection."),
                }).await;
                return Err(e);
            }
            None => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of nothing return from proxy connection.");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of nothing return from proxy connection."),
                }).await;
                return  Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of nothing return from proxy connection.")));
            }
        };

        let PpaassProxyMessage {
            payload: proxy_message_payload,
            ..
        } = proxy_message;
        let PpaassProxyMessagePayload::Tcp(ProxyTcpPayload::Init { result, .. }) =
            proxy_message_payload
        else {
            error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of did not receive init result from proxy connection.");
            publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of did not receive init result from proxy connection."),
                }).await;
            return  Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of did not receive init result from proxy connection.")));
        };
        let tunnel_id = match result {
            ProxyTcpInitResult::Success(tunnel_id) => tunnel_id,
            ProxyTcpInitResult::Fail(reason) => {
                error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of reason: {reason:?}");
                publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of reason: {reason:?}")
                }).await;
                return Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of reason: {reason:?}")));
            }
        };

        debug!("Client socks5 tcp connection [{src_address}] success to initialize tcp connection with proxy on tunnel: {tunnel_id}");
        let socks5_init_success_result = Socks5InitCommandResult::new(
            Socks5InitCommandResultStatus::Succeeded,
            Some(dst_address.clone().try_into()?),
        );
        if let Err(e) = socks5_init_framed.send(socks5_init_success_result).await {
            error!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error happen when send init response command to client: {e:?}");
            publish_server_event(server_event_tx, AgentServerEvent::TunnelInitializeFail {
                    client_socket_address:client_socket_address.clone(),
                    dst_address: Some(dst_address.clone()),
                    src_address: Some(src_address.clone()),
                    reason: format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error happen when send init response command to client.")
                }).await;
            return Err(AgentServerError::Other(format!("Client connection [{client_socket_address}] initialize socks5 tunnel from [{src_address}] to [{dst_address}] fail because of error happen when send init response command to client: {e:?}")));
        };
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = socks5_init_framed.into_parts();
        debug!(
            "Client tcp connection [{src_address}] success to do sock5 handshake begin to relay."
        );
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
            config,
            TunnelTcpDataRelay {
                tunnel_id,
                client_tcp_stream,
                client_socket_address,
                src_address,
                dst_address,
                proxy_connection_write,
                proxy_connection_read,
                init_data: None,
                payload_encryption,
                upload_bytes_amount,
                download_bytes_amount,
                stopped_status,
            },
            server_event_tx,
        )
        .await?;
        Ok(())
    }
}
