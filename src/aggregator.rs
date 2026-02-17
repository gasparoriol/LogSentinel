use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use regex::Regex;
use std::future::Future;

pub struct LogAggregator {
    multiline_regex: Option<Regex>,
    timeout: Duration,
    buffer: String,
}

impl LogAggregator {
    pub fn new(multiline_pattern: Option<String>, timeout_ms: u64) -> Self {
        let multiline_regex = multiline_pattern
            .and_then(|p| Regex::new(&p).ok());
            
        Self {
            multiline_regex,
            timeout: Duration::from_millis(timeout_ms),
            buffer: String::new(),
        }
    }

    pub async fn run<F, Fut>(mut self, mut rx: mpsc::Receiver<String>, process: F)
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let mut sleep_handle = Box::pin(sleep(self.timeout));
        let mut timer_active = false;

        loop {
            tokio::select! {
                Some(line) = rx.recv() => {
                    let clean_line = line.trim_end().to_string();

                    let is_new_entry = if let Some(re) = &self.multiline_regex {
                        re.is_match(&clean_line)
                    } else {
                        true
                    };

                    if is_new_entry {
                        if !self.buffer.is_empty() {
                            process(self.buffer.clone()).await;
                            self.buffer.clear();
                        }
                    } else if !self.buffer.is_empty() {
                        self.buffer.push('\n');
                    }
                    
                    self.buffer.push_str(&clean_line);
                    
                    // Reset timer whenever we receive data
                    sleep_handle = Box::pin(sleep(self.timeout));
                    timer_active = true;
                }
                _ = &mut sleep_handle, if timer_active && !self.buffer.is_empty() => {
                    process(self.buffer.clone()).await;
                    self.buffer.clear();
                    timer_active = false;
                }
                else => {
                    // Channel closed, process remaining buffer
                    if !self.buffer.is_empty() {
                        process(self.buffer.clone()).await;
                        self.buffer.clear();
                    }
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn test_aggregator_no_multiline() {
        let (tx, rx) = mpsc::channel(10);
        let results = Arc::new(Mutex::new(Vec::new()));
        let results_clone = Arc::clone(&results);

        let aggregator = LogAggregator::new(None, 100);
        
        tx.send("line1".to_string()).await.unwrap();
        tx.send("line2".to_string()).await.unwrap();
        drop(tx);

        aggregator.run(rx, move |log| {
            let res = Arc::clone(&results_clone);
            async move {
                res.lock().unwrap().push(log);
            }
        }).await;

        let res = results.lock().unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], "line1");
        assert_eq!(res[1], "line2");
    }

    #[tokio::test]
    async fn test_aggregator_with_multiline() {
        let (tx, rx) = mpsc::channel(10);
        let results = Arc::new(Mutex::new(Vec::new()));
        let results_clone = Arc::clone(&results);

        // Lines starting with '[' are new entries
        let aggregator = LogAggregator::new(Some(r"^\[".to_string()), 100);
        
        tx.send("[entry1] start".to_string()).await.unwrap();
        tx.send("  continued".to_string()).await.unwrap();
        tx.send("[entry2] start".to_string()).await.unwrap();
        drop(tx);

        aggregator.run(rx, move |log| {
            let res = Arc::clone(&results_clone);
            async move {
                res.lock().unwrap().push(log);
            }
        }).await;

        let res = results.lock().unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], "[entry1] start\n  continued");
        assert_eq!(res[1], "[entry2] start");
    }
}
