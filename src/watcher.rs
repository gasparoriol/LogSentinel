use notify::{Watcher, RecursiveMode, Config, Event};
use std::path::Path;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::fs::File;
use tokio::sync::mpsc;

pub struct LogWatcher {
    path: String,
}

impl LogWatcher {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string() }
    }

    pub async fn watch(&self, tx: mpsc::Sender<String>) -> notify::Result<()> {
        let path = self.path.clone();
        let (sync_tx, mut sync_rx) = std::sync::mpsc::channel();

        let mut watcher = notify::RecommendedWatcher::new(sync_tx, Config::default())?;
        watcher.watch(Path::new(&path), RecursiveMode::NonRecursive)?;

        let file = File::open(&path).expect("Could not open log file");
        let mut reader = BufReader::new(file);
        let mut pos = reader.seek(SeekFrom::End(0))?;

        println!("Watching file changes...");

        for res in sync_rx {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        let mut file = File::open(&path).expect("Error opening file");
                        file.seek(SeekFrom::Start(pos))?;
                        let mut reader = BufReader::new(file);

                        let mut line = String::new();
                        while reader.read_line(&mut line)? > 0 {
                            tx.send(line.clone()).await.unwrap();
                            line.clear();
                        }
                        pos = reader.stream_position()?;
                    }
                }
                Err(e) => println!("Error in watcher: {:?}", e),
            }
        }
        Ok(())
    }
}