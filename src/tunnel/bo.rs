use crate::{config::AgentServerConfig, proxy::ProxyConnectionFactory};
use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::values::address::UnifiedAddress;
use std::sync::{atomic::AtomicU64, Arc};
pub(crate) struct TunnelCreateRequest<'a, F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub src_address: UnifiedAddress,
    pub client_socket_address: UnifiedAddress,
    pub config: Arc<AgentServerConfig>,
    pub proxy_connection_factory: Arc<ProxyConnectionFactory<'a, F>>,
    pub upload_bytes_amount: Arc<AtomicU64>,
    pub download_bytes_amount: Arc<AtomicU64>,
}
