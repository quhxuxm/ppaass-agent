use std::str::FromStr;
use std::sync::Arc;
use std::{net::SocketAddr, time::Duration};

use ppaass_crypto::crypto::RsaCryptoFetcher;
use tokio::{net::TcpStream, time::timeout};

use tokio_io_timeout::TimeoutStream;
use tokio_tfo::TfoStream;
use tokio_util::codec::Framed;
use tracing::{debug, error};

use crate::error::AgentServerError;
use crate::{codec::PpaassProxyEdgeCodec, config::AgentServerConfig};

pub(crate) struct ProxyConnectionFactory<F>
where
    F: RsaCryptoFetcher,
{
    proxy_addresses: Vec<SocketAddr>,
    config: Arc<AgentServerConfig>,
    rsa_crypto_fetcher: Arc<F>,
}

impl<F> ProxyConnectionFactory<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub(crate) fn new(
        config: Arc<AgentServerConfig>,
        rsa_crypto_fetcher: F,
    ) -> Result<Self, AgentServerError> {
        let proxy_addresses_configuration = config.proxy_addresses();
        let proxy_addresses: Vec<SocketAddr> = proxy_addresses_configuration
            .iter()
            .filter_map(|addr| SocketAddr::from_str(addr).ok())
            .collect::<Vec<SocketAddr>>();
        if proxy_addresses.is_empty() {
            error!("No available proxy address for runtime to use.");
            panic!("No available proxy address for runtime to use.")
        }
        Ok(Self {
            proxy_addresses,
            config,
            rsa_crypto_fetcher: Arc::new(rsa_crypto_fetcher),
        })
    }

    pub(crate) async fn create_proxy_connection(
        &self,
    ) -> Result<Framed<TimeoutStream<TfoStream>, PpaassProxyEdgeCodec<Arc<F>>>, AgentServerError>
    {
        debug!("Take proxy connection from pool.");
        let proxy_tcp_stream = match timeout(
            Duration::from_secs(self.config.connect_to_proxy_timeout()),
            TcpStream::connect(self.proxy_addresses.as_slice()),
        )
        .await
        {
            Err(_) => {
                error!("Fail connect to proxy because of timeout.");
                return Err(AgentServerError::Other(format!(
                    "Fail to create proxy connection because of timeout: {}",
                    self.config.connect_to_proxy_timeout()
                )));
            }
            Ok(Ok(proxy_tcp_stream)) => proxy_tcp_stream,
            Ok(Err(e)) => {
                error!("Fail connect to proxy because of error: {e:?}");
                return Err(AgentServerError::StdIo(e));
            }
        };
        debug!("Success connect to proxy.");
        proxy_tcp_stream.set_nodelay(true)?;
        proxy_tcp_stream.set_linger(None)?;
        let proxy_tcp_stream = TfoStream::from(proxy_tcp_stream);
        let mut proxy_tcp_stream = TimeoutStream::new(proxy_tcp_stream);
        proxy_tcp_stream.set_read_timeout(Some(Duration::from_secs(
            self.config.proxy_connection_read_timeout(),
        )));
        proxy_tcp_stream.set_write_timeout(Some(Duration::from_secs(
            self.config.proxy_connection_write_timeout(),
        )));
        let proxy_connection = Framed::with_capacity(
            proxy_tcp_stream,
            PpaassProxyEdgeCodec::new(self.config.compress(), self.rsa_crypto_fetcher.clone()),
            self.config.proxy_send_buffer_size(),
        );
        Ok(proxy_connection)
    }
}
