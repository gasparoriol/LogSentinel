use linemux::MuxedLines;
use tokio::sync::mpsc;

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

        println!("🚀 Watching changes in: {}", self.path);

        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line.line().to_string()).await.is_err() {
                break;
            }
        }

        Ok(())
    }
}