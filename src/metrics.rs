use prometheus::{Registry, Counter, Histogram, HistogramOpts, opts, register_counter_with_registry, register_histogram_with_registry};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref LOG_LINES_PROCESSED: Counter = register_counter_with_registry!(
        opts!("log_sentinel_lines_processed_total", "Total number of log lines read and processed"),
        REGISTRY
    ).unwrap();

    pub static ref SUSPICIOUS_LOGS: Counter = register_counter_with_registry!(
        opts!("log_sentinel_suspicious_logs_total", "Total number of logs that matched suspicious patterns"),
        REGISTRY
    ).unwrap();

    pub static ref ANALYSIS_BATCHES: Counter = register_counter_with_registry!(
        opts!("log_sentinel_analysis_batches_total", "Total number of batches sent to AI for analysis"),
        REGISTRY
    ).unwrap();

    pub static ref CONFIRMED_THREATS: Counter = register_counter_with_registry!(
        opts!("log_sentinel_confirmed_threats_total", "Total number of security threats confirmed by AI"),
        REGISTRY
    ).unwrap();

    pub static ref DISPATCH_FAILURES: Counter = register_counter_with_registry!(
        opts!("log_sentinel_dispatch_failures_total", "Total number of errors when sending alerts to sinks"),
        REGISTRY
    ).unwrap();

    pub static ref ANALYSIS_LATENCY: Histogram = register_histogram_with_registry!(
        HistogramOpts::new("log_sentinel_analysis_latency_seconds", "AI analysis latency in seconds")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]),
        REGISTRY
    ).unwrap();
}
