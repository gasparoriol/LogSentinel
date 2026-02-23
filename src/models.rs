use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogSource {
  Tomcat,
  Nginx,
  Dotnet,
  Generic,
}
impl LogSource {
  pub fn get_context(&self) -> &str {
    match self {
      LogSource::Tomcat => "Java/Tomcat (search JVM errors, Spring Security and UUID leaks)",
      LogSource::Dotnet => ".NET Core (search middleware exceptions and ASP.NET attacks)",
      LogSource::Nginx => "Nginx (search route scans and 4xx/5xx errors)",
      LogSource::Generic => "Generic server",
    }
  }
  pub fn as_str(&self) -> &'static str {
    match self {
      LogSource::Tomcat => "Tomcat",
      LogSource::Nginx => "Nginx",
      LogSource::Dotnet => "Dotnet",
      LogSource::Generic => "Generic",
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LogLevel {
  Info,
  Warning,
  Error,
  Debug,
  Trace,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogSourceDetail {
  pub name: String,
  pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
  pub level: LogLevel,
  pub reason: String,
  pub source: LogSourceDetail,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityAlert {
    pub timestamp: String,
    pub source_type: String,
    pub severity: String,      // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    pub attack_type: String,   // "SQLi", "Brute Force", etc.
    pub description: String,
    pub original_log: String,
}

impl std::fmt::Display for SecurityAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ALERT - Severity: {}, Type: {}, Description: {}", 
               self.severity, self.attack_type, self.description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_source_context() {
        assert!(LogSource::Tomcat.get_context().contains("Tomcat"));
        assert!(LogSource::Nginx.get_context().contains("Nginx"));
        assert!(LogSource::Dotnet.get_context().contains(".NET Core"));
        assert!(LogSource::Generic.get_context().contains("genérico"));
    }

    #[test]
    fn test_log_source_as_str() {
        assert_eq!(LogSource::Tomcat.as_str(), "Tomcat");
        assert_eq!(LogSource::Nginx.as_str(), "Nginx");
        assert_eq!(LogSource::Dotnet.as_str(), "Dotnet");
        assert_eq!(LogSource::Generic.as_str(), "Generic");
    }

    #[test]
    fn test_security_alert_display() {
        let alert = SecurityAlert {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            source_type: "Tomcat".to_string(),
            severity: "HIGH".to_string(),
            attack_type: "SQLi".to_string(),
            description: "Potential SQL injection".to_string(),
            original_log: "SELECT * FROM users".to_string(),
        };
        let display = format!("{}", alert);
        assert!(display.contains("HIGH"));
        assert!(display.contains("SQLi"));
        assert!(display.contains("Potential SQL injection"));
    }
}
