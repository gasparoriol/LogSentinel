use notify::{Watcher, RecursiveMode, Config};
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
        
        // Spawn a blocking task for the file watcher
        tokio::task::spawn_blocking(move || {
            let (sync_tx, sync_rx) = std::sync::mpsc::channel();
            
            let mut watcher = match notify::RecommendedWatcher::new(sync_tx, Config::default()) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Failed to create watcher: {:?}", e);
                    return;
                }
            };
            
            if let Err(e) = watcher.watch(Path::new(&path), RecursiveMode::NonRecursive) {
                eprintln!("Failed to start watching {}: {:?}", path, e);
                return;
            }

            let file = match File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Could not open log file {}: {:?}", path, e);
                    return;
                }
            };
            
            let mut reader = BufReader::new(file);
            let mut pos = match reader.seek(SeekFrom::End(0)) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to seek to end: {:?}", e);
                    return;
                }
            };

            println!("Watching file changes...");

            for res in sync_rx {
                match res {
                    Ok(event) => {
                        // println!("Event received: {:?}", event); // Debug logging
                        if event.kind.is_modify() {
                            let mut file = match File::open(&path) {
                                Ok(f) => f,
                                Err(e) => {
                                    eprintln!("Error re-opening file: {:?}", e);
                                    continue;
                                }
                            };
                            
                            if let Err(e) = file.seek(SeekFrom::Start(pos)) {
                                eprintln!("Error seeking file: {:?}", e);
                                continue;
                            }
                            
                            let mut reader = BufReader::new(file);
                            let mut line = String::new();
                            
                            loop {
                                match reader.read_line(&mut line) {
                                    Ok(0) => break, // EOF
                                    Ok(_) => {
                                        // We need to block_on to send to async channel or use blocking send if available
                                        // But tx is mpsc::Sender (async). 
                                        // Better: use blocking_send if using mpsc::blocking (not std) or Handle::current().block_on
                                        // actually tokio::sync::mpsc::Sender has blocking_send
                                        if let Err(_) = tx.blocking_send(line.clone()) {
                                            eprintln!("Receiver dropped");
                                            return; 
                                        }
                                        line.clear();
                                    }
                                    Err(e) => {
                                        eprintln!("Error reading line: {:?}", e);
                                        break;
                                    }
                                }
                            }
                            // Update position
                            match reader.stream_position() {
                                Ok(new_pos) => pos = new_pos,
                                Err(e) => eprintln!("Error getting stream position: {:?}", e),
                            }
                        }
                    }
                    Err(e) => println!("Error in watcher: {:?}", e),
                }
            }
        }).await.map_err(|e| notify::Error::generic(&e.to_string()))?;
        
        Ok(())
    }
}