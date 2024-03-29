use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use crate::{config::AgentConfig, error::AgentError};
use crate::{
    crypto::AgentServerRsaCryptoFetcher,
    proxy::ProxyConnectionFactory,
    transport::dispatcher::{ClientTransport, ClientTransportDispatcher},
};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, error, info};

const AGENT_SERVER_RUNTIME_NAME: &str = "AGENT-SERVER";

pub struct AgentServerGuard {
    join_handle: JoinHandle<()>,
    runtime: Runtime,
}

impl AgentServerGuard {
    pub fn blocking(&self) {
        self.runtime.block_on(async {
            while !self.join_handle.is_finished() {
                sleep(Duration::from_millis(100)).await;
            }
        });
    }
}

pub struct AgentServer {
    config: Arc<AgentConfig>,
    runtime: Runtime,
    client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
}

impl AgentServer {
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        let config = Arc::new(config);
        let rsa_crypto_fetcher = AgentServerRsaCryptoFetcher::new(&config)?;
        let proxy_connection_factory =
            ProxyConnectionFactory::new(config.clone(), rsa_crypto_fetcher)?;
        let client_transport_dispatcher =
            ClientTransportDispatcher::new(config.clone(), proxy_connection_factory);
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .thread_name(AGENT_SERVER_RUNTIME_NAME)
            .worker_threads(config.worker_thread_number())
            .build()?;
        Ok(Self {
            config,
            runtime,
            client_transport_dispatcher: Arc::new(client_transport_dispatcher),
        })
    }
    async fn accept_client_connection(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), AgentError> {
        let (client_tcp_stream, client_socket_address) = tcp_listener.accept().await?;
        client_tcp_stream.set_nodelay(true)?;
        Ok((client_tcp_stream, client_socket_address))
    }

    async fn run(
        config: Arc<AgentConfig>,
        client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
    ) -> Result<(), AgentError> {
        let agent_server_bind_addr = if config.ipv6() {
            format!("::1:{}", config.port())
        } else {
            format!("0.0.0.0:{}", config.port())
        };
        info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
        let tcp_listener = TcpListener::bind(&agent_server_bind_addr).await?;
        loop {
            match Self::accept_client_connection(&tcp_listener).await {
                Ok((client_tcp_stream, client_socket_address)) => {
                    debug!("Accept client tcp connection on address: {client_socket_address}");
                    Self::handle_client_connection(
                        client_tcp_stream,
                        client_socket_address,
                        client_transport_dispatcher.clone(),
                    );
                }
                Err(e) => {
                    error!("Agent server fail to accept client connection because of error: {e:?}");
                    continue;
                }
            }
        }
    }

    pub fn start(self) -> AgentServerGuard {
        let join_handle = self.runtime.spawn(async move {
            if let Err(e) = Self::run(self.config, self.client_transport_dispatcher).await {
                error!("Fail to start agent server because of error: {e:?}");
            }
        });
        AgentServerGuard {
            join_handle,
            runtime: self.runtime,
        }
    }

    fn handle_client_connection(
        client_tcp_stream: TcpStream,
        client_socket_address: SocketAddr,
        client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
    ) {
        tokio::spawn(async move {
            let client_transport = client_transport_dispatcher
                .dispatch(client_tcp_stream, client_socket_address)
                .await?;
            match client_transport {
                ClientTransport::Socks5(socks5_transport) => {
                    socks5_transport.process().await?;
                }
                ClientTransport::Http(http_transport) => {
                    http_transport.process().await?;
                }
            };
            debug!("Client transport [{client_socket_address}] complete to serve.");
            Ok::<(), AgentError>(())
        });
    }
}
