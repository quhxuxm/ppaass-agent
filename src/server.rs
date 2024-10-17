use crate::{
    command::AgentServerCommand, config::AgentServerConfig, error::AgentServerError,
    event::AgentServerEvent, publish_server_event,
};
use crate::{
    crypto::AgentServerRsaCryptoFetcher,
    proxy::ProxyConnectionFactory,
    tunnel::dispatcher::{ClientDispatcher, Tunnel},
};
use anyhow::Result;
use ppaass_protocol::message::values::address::UnifiedAddress;
use std::{net::SocketAddr, sync::atomic::AtomicBool};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::{net::TcpListener, time::interval};
use tokio_io_timeout::TimeoutStream;
use tokio_tfo::{TfoListener, TfoStream};
use tracing::{debug, error, info};
const AGENT_SEVER_EVENT_CHANNEL_BUF: usize = 1024;
const AGENT_SEVER_COMMAND_CHANNEL_BUF: usize = 1024;
const ONE_MB: u64 = 1024 * 1024;

pub struct AgentServer {
    config: Arc<AgentServerConfig>,
    client_dispatcher: ClientDispatcher<AgentServerRsaCryptoFetcher>,
}

impl AgentServer {
    pub fn new(config: Arc<AgentServerConfig>) -> Result<Self> {
        let rsa_crypto_fetcher = AgentServerRsaCryptoFetcher::new(&config)?;
        let proxy_connection_factory =
            ProxyConnectionFactory::new(config.clone(), &rsa_crypto_fetcher)?;
        let client_dispatcher = ClientDispatcher::new(config.clone(), proxy_connection_factory);
        Ok(Self {
            config,
            client_dispatcher,
        })
    }

    pub fn start(self) -> (Sender<AgentServerCommand>, Receiver<AgentServerEvent>) {
        let (server_event_tx, server_event_rx) = channel(AGENT_SEVER_EVENT_CHANNEL_BUF);
        let (server_command_tx, mut server_command_rx) = channel(AGENT_SEVER_COMMAND_CHANNEL_BUF);
        let config = self.config;
        let client_dispatcher = self.client_dispatcher;
        let upload_bytes_amount: Arc<AtomicU64> = Default::default();
        let download_bytes_amount: Arc<AtomicU64> = Default::default();
        let stopped_status: Arc<AtomicBool> = Default::default();
        tokio::spawn(async move {
            let agent_server_bind_addr = if config.ipv6() {
                format!("::1:{}", config.port())
            } else {
                format!("0.0.0.0:{}", config.port())
            };
            info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
            let tcp_listener = match TcpListener::bind(&agent_server_bind_addr).await {
                Ok(tcp_listener) => tcp_listener,
                Err(e) => {
                    error!(
                        "Fail to listen tcp port {} because of error: {e:?}",
                        config.port()
                    );
                    publish_server_event(
                        &server_event_tx,
                        AgentServerEvent::ServerStartFail {
                            listening_port: config.port(),
                            reason: format!("Fail to listen tcp port: {}", config.port()),
                        },
                    )
                    .await;
                    return;
                }
            };
            let tcp_listener = match TfoListener::from_tokio(tcp_listener) {
                Ok(tcp_listener) => tcp_listener,
                Err(e) => {
                    error!("Fail to use fast open on tcp listener because of error: {e:?}");
                    return;
                }
            };

            publish_server_event(
                &server_event_tx,
                AgentServerEvent::ServerStartSuccess(config.port()),
            )
            .await;

            // Start the network state event task
            let upload_bytes_amount = upload_bytes_amount.clone();
            let download_bytes_amount = download_bytes_amount.clone();
            let server_event_tx = server_event_tx.clone();
            let server_event_tick_interval_val = config.server_signal_tick_interval();
            let mb_per_second_div_base = (server_event_tick_interval_val * ONE_MB) as f64;
            let mut server_event_tick_interval =
                interval(Duration::from_secs(server_event_tick_interval_val));

            loop {
                let upload_bytes_amount_pre_val = upload_bytes_amount.fetch_add(0, Relaxed);
                let download_bytes_amount_pre_val = download_bytes_amount.fetch_add(0, Relaxed);
                tokio::select! {
                    // Listening to server command
                    server_command = server_command_rx.recv() => {
                        match server_command {
                            Some(server_command) => {
                                match server_command {
                                    AgentServerCommand::Stop => {
                                        info!("Agent server stopped because of receive stop command.");
                                        stopped_status.swap(true, Relaxed);
                                        publish_server_event(&server_event_tx, AgentServerEvent::ServerStopSuccess).await;
                                        return;
                                    },
                                }
                            },
                            None => {
                                info!("Agent server stopped because of no command tx.");
                                publish_server_event(&server_event_tx, AgentServerEvent::ServerStopSuccess).await;
                                return;
                            },
                        }
                    }
                    // Send network
                    _ = server_event_tick_interval.tick() => {
                        let upload_bytes_amount_current_val =
                            upload_bytes_amount.fetch_add(0, Relaxed);
                        let download_bytes_amount_current_val =
                            download_bytes_amount.fetch_add(0, Relaxed);

                        let upload_mb_per_second =
                            (upload_bytes_amount_current_val - upload_bytes_amount_pre_val) as f64
                                / mb_per_second_div_base;

                        let download_mb_per_second = (download_bytes_amount_current_val
                            - download_bytes_amount_pre_val)
                            as f64
                            / mb_per_second_div_base;

                        publish_server_event(
                            &server_event_tx,
                            AgentServerEvent::NetworkState {
                                upload_mb_amount: upload_bytes_amount_current_val as f64
                                    / ONE_MB as f64,
                                upload_mb_per_second,
                                download_mb_amount: download_bytes_amount_current_val as f64
                                    / ONE_MB as f64,
                                download_mb_per_second,
                            },
                        )
                        .await;
                    }
                    // Accepting client connection
                    client_accept_result = Self::accept_client_connection(&config, &tcp_listener) => {
                        match client_accept_result{
                            Ok((client_tcp_stream, client_socket_address)) => {
                                debug!("Accept client tcp connection on address: {client_socket_address}");
                                Self::handle_client_connection(
                                    client_tcp_stream,
                                    client_socket_address.into(),
                                    client_dispatcher.clone(),
                                    server_event_tx.clone(),
                                    upload_bytes_amount.clone(),
                                    download_bytes_amount.clone(),
                                    stopped_status.clone()
                                );
                            }
                            Err(e) => {
                                error!("Agent server fail to accept client connection because of error: {e:?}");
                                continue;
                            }
                        }
                    }
                }
            }
        });
        (server_command_tx, server_event_rx)
    }

    async fn accept_client_connection(
        config: &AgentServerConfig,
        tcp_listener: &TfoListener,
    ) -> Result<(TimeoutStream<TfoStream>, SocketAddr), AgentServerError> {
        let (client_tcp_stream, client_socket_address) = tcp_listener.accept().await?;
        client_tcp_stream.set_nodelay(true)?;
        let mut client_tcp_stream = TimeoutStream::new(client_tcp_stream);
        client_tcp_stream.set_read_timeout(Some(Duration::from_secs(
            config.client_connection_read_timeout(),
        )));
        client_tcp_stream.set_write_timeout(Some(Duration::from_secs(
            config.client_connection_write_timeout(),
        )));
        Ok((client_tcp_stream, client_socket_address))
    }

    fn handle_client_connection(
        client_tcp_stream: TimeoutStream<TfoStream>,
        client_socket_address: UnifiedAddress,
        client_dispatcher: ClientDispatcher<AgentServerRsaCryptoFetcher>,
        server_event_tx: Sender<AgentServerEvent>,
        upload_bytes_amount: Arc<AtomicU64>,
        download_bytes_amount: Arc<AtomicU64>,
        stopped_status: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            let tunnel = match client_dispatcher
                .dispatch(
                    client_tcp_stream,
                    &client_socket_address,
                    &server_event_tx,
                    upload_bytes_amount,
                    download_bytes_amount,
                )
                .await
            {
                Ok(tunnel) => tunnel,
                Err(e) => {
                    error!("Fail to dispatch client connection [{client_socket_address}] to tunnel because of error: {e:?}");
                    return;
                }
            };

            match tunnel {
                Tunnel::Socks5(tunnel) => {
                    if let Err(e) = tunnel.process(&server_event_tx, stopped_status).await {
                        error!("Fail to process socks5 tunnel for client connection [{client_socket_address}] because of error: {e:?}");
                    }
                }
                Tunnel::Http(tunnel) => {
                    if let Err(e) = tunnel.process(&server_event_tx, stopped_status).await {
                        error!("Fail to process http tunnel for client connection [{client_socket_address}] because of error: {e:?}");
                    }
                }
            }
        });
    }
}
