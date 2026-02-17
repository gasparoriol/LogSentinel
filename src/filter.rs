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
        if self.config.case_insensitive_patterns.iter().any(|p| upper_line.contains(&p.to_uppercase())) ||
           self.config.error_codes.iter().any(|p| upper_line.contains(&p.to_uppercase())) ||
           self.config.nmap_patterns.iter().any(|p| upper_line.contains(&p.to_uppercase())) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogFilterConfig;

    fn mock_config() -> LogFilterConfig {
        LogFilterConfig {
            exact_patterns: vec!["admin".to_string()],
            case_insensitive_patterns: vec!["Password".to_string()],
            error_codes: vec!["err-500".to_string()],
            nmap_patterns: vec!["NmapScript".to_string()],
            multiline_pattern: None,
        }
    }

    #[test]
    fn test_exact_pattern() {
        let filter = LogFilter::new(mock_config());
        assert!(filter.is_suspicious("User admin logged in"));
        assert!(!filter.is_suspicious("User guest logged in"));
    }

    #[test]
    fn test_case_insensitive_pattern() {
        let filter = LogFilter::new(mock_config());
        assert!(filter.is_suspicious("Change password for user"));
        assert!(filter.is_suspicious("CHANGE PASSWORD FOR USER"));
    }

    #[test]
    fn test_sqli_detection() {
        let filter = LogFilter::new(mock_config());
        assert!(filter.is_suspicious("' OR '1'='1' --"));
        assert!(filter.is_suspicious("SELECT * FROM users; /*"));
    }

    #[test]
    fn test_xss_detection() {
        let filter = LogFilter::new(mock_config());
        assert!(filter.is_suspicious("<SCRIPT>alert(1)</SCRIPT>"));
        assert!(filter.is_suspicious("<IMG SRC=x>"));
    }

    #[test]
    fn test_error_and_nmap() {
        let filter = LogFilter::new(mock_config());
        assert!(filter.is_suspicious("Critical error ERR-500 occurred"));
        assert!(filter.is_suspicious("Detected NmapScript scan"));
    }

    #[test]
    fn test_benign_log() {
        let filter = LogFilter::new(mock_config());
        assert!(!filter.is_suspicious("General information log message"));
    }
}
