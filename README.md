# LogSentinel

LogSentinel is a lightweight, AI-powered log analysis tool designed to detect security threats in real-time. It uses a hybrid approach combining traditional pattern matching with advanced Large Language Models (LLMs) to identify anomalies, attacks, and vulnerabilities in your application logs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

## Features

- **Real-time Analysis**: Monitors log files in real-time and detects threats as they happen.
- **Hybrid Detection**: Combines traditional pattern matching with AI-powered analysis for comprehensive threat detection.
- **Multi-Source Support**: Supports multiple log sources including Tomcat, Nginx, Apache, and .NET.
- **Lightweight**: Written in Rust for maximum performance and minimal resource usage.
- **Portable**: Cross-platform support for Linux, Windows, and macOS.

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo (Rust package manager)

### Building from Source

1. Clone the repository:

```bash
git clone https://github.com/gasparoriol/LogSentinel.git
cd LogSentinel
```

2. Build the project:

```bash
cargo build --release
```

## Usage

### Basic Usage

```bash
Usage: LogSentinel [OPTIONS]

Options:
  -c, --config <CONFIG>              
  -d, --daemon                       
      --api-key-file <API_KEY_FILE>  
  -h, --help                         Print help
  -V, --version                      Print version
```

### Configuration

The configuration file is located at `/path/to/config.toml`. It contains the following fields:

- `log_sources`: A list of log sources to monitor.
- `llm_provider`: The LLM provider to use for analysis.
- `filter_config`: The filter configuration.

### Example Configuration

```
log_path = "catalina.out"
source = "tomcat"

[server]
provider = "ollama" # or "openai" or "gemini"
model = "llama3"
api_url = "http://localhost:11434/api/generate"
api_key = "sk-..." # Only for openai or gemini    

[bff]
url = "http://localhost:3000/api/alerts"
token = "secret"
enabled = false

[logger]
path = "security_audit.log"
enabled = true

[email]
recipient = "[EMAIL_ADDRESS]"
from = "[EMAIL_ADDRESS]"
api_url = "http://smtp-relay/api/send"
enabled = false

[rats]
burst = 3
period_seconds = 30

[filter]
exact_patterns = [
    "PHNjc",
    "ID0i",
    "U0VMRUNU",
    "RElTVElOQ1Q",
    "PHNjcmlwdD",
    "Trinity"
]
case_insensitive_patterns = [
    "../", "<?PHP", "CHMOD", "CAT /ETC", "SELECT",
    "DROP", "OR", "ADMIN", "PASSWORD", "ETC/PASSWD", "SCRIPT", "ALERT(",
    "..\\", "..%2F..%2F", "../etc/passwd", "../etc/shadow", "../etc/hosts"
]
error_codes = ["403", "500", "502", "503", "504"]
nmap_patterns = [
    "NMAP",
    "NSE/",
    "HNAP1",
    "NESSUS",
    "ZGRAB",
    "CENSYS"
]
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


