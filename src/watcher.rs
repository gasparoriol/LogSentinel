use linemux::MuxedLines;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct LogWatcher {
    path: String,
}

impl LogWatcher {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string() }
    }

    pub async fn watch(&self, tx: mpsc::Sender<String>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut lines = MuxedLines::new()?;
        
        lines.add_file_from_start(&self.path).await?;

        info!(path = %self.path, "Watching file for changes");

        while let Ok(Some(line)) = lines.next_line().await {
            let line_str = line.line().to_string();
            debug!(line = %line_str, "New log line received");
            if tx.send(line_str).await.is_err() {
                warn!("Log channel closed, stopping watcher");
                break;
            }
        }

        Ok(())
    }
}