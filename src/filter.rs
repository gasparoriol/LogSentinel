use crate::config::LogFilterConfig;

pub struct LogFilter {
    config: LogFilterConfig,
}

impl LogFilter {
    pub fn new(config: LogFilterConfig) -> Self {
        Self { config }
    }

    pub fn is_suspicious(&self, line: &str) -> bool {
        // Check signatures from the external file
        for sig in &self.config.signatures {
            match sig.sig_type {
                crate::config::SignatureType::Exact => {
                    if line.contains(&sig.pattern) {
                        return true;
                    }
                }
                crate::config::SignatureType::CaseInsensitive => {
                    if line.to_uppercase().contains(&sig.pattern.to_uppercase()) {
                        return true;
                    }
                }
                crate::config::SignatureType::Regex => {
                    if let Ok(re) = regex::Regex::new(&sig.pattern) {
                        if re.is_match(line) {
                            return true;
                        }
                    }
                }
            }
        }

        // Keep checking for error codes
        let upper_line = line.to_uppercase();
        if self.config.error_codes.iter().any(|p| upper_line.contains(&p.to_uppercase())) {
            return true;
        }

        // Keep the heuristic rules for now
        if line.contains("<") && (line.contains("SCRIPT") || line.contains("IMG") || line.contains("SVG")) {
            return true;
        }

        if line.contains("'") || line.contains("--") || line.contains("/*") {
            if line.contains(" OR ") || line.contains(" AND ") || line.contains("SELECT") {
                return true;
            }
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
            signatures_path: "mock.toml".to_string(),
            error_codes: vec!["err-500".to_string()],
            multiline_pattern: None,
            signatures: vec![
                crate::config::ThreatSignature {
                    id: "test-exact".to_string(),
                    pattern: "admin".to_string(),
                    sig_type: crate::config::SignatureType::Exact,
                    description: "test".to_string(),
                },
                crate::config::ThreatSignature {
                    id: "test-ci".to_string(),
                    pattern: "Password".to_string(),
                    sig_type: crate::config::SignatureType::CaseInsensitive,
                    description: "test".to_string(),
                },
            ],
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
        // Nmap is now handled via signatures, which mock_config doesn't have in its basic list anymore
        // but we can add one for the test
    }

    #[test]
    fn test_benign_log() {
        let filter = LogFilter::new(mock_config());
        assert!(!filter.is_suspicious("General information log message"));
    }
}
