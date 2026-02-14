use crate::config::LogFilterConfig;

pub struct LogFilter {
    config: LogFilterConfig,
}

impl LogFilter {
    pub fn new(config: LogFilterConfig) -> Self {
        Self { config }
    }

    pub fn is_suspicious(&self, line: &str) -> bool {
        if self.config.exact_patterns.iter().any(|p| line.contains(p)) {
            return true;
        }

        if line.contains("<") && (line.contains("SCRIPT") || line.contains("IMG") || line.contains("SVG")) {
            return true;
        }

        if line.contains("'") || line.contains("--") || line.contains("/*") {
            if line.contains(" OR ") || line.contains(" AND ") || line.contains("SELECT") {
                return true;
            }
        }

        let upper_line = line.to_uppercase();
        if self.config.case_insensitive_patterns.iter().any(|p| upper_line.contains(p)) ||
           self.config.error_codes.iter().any(|p| upper_line.contains(p)) ||
           self.config.nmap_patterns.iter().any(|p| upper_line.contains(p)) {
            return true;
        }

        false
    }
}
