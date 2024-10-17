use event::AgentServerEvent;
use tokio::sync::mpsc::Sender;
use tracing::error;
pub mod command;
pub mod config;
mod crypto;
mod error;
pub mod event;
pub mod log;
mod proxy;
pub mod server;
mod tunnel;

pub const SOCKS_V5: u8 = 5;
pub const SOCKS_V4: u8 = 4;

pub async fn publish_server_event(
    server_event_tx: &Sender<AgentServerEvent>,
    event: AgentServerEvent,
) {
    if server_event_tx.is_closed() {
        return;
    }
    if let Err(e) = server_event_tx.send(event).await {
        error!("Fail to publish server event because of error: {e:?}");
    }
}
