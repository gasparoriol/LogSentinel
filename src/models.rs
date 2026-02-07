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
      LogSource::Tomcat => "Java/Tomcat (busca errores JVM, Spring Security y fugas de UUIDs)",
      LogSource::Dotnet => ".NET Core (busca excepciones de middleware y ataques ASP.NET)",
      LogSource::Nginx => "Nginx (busca escaneos de rutas y errores 4xx/5xx)",
      LogSource::Generic => "Servidor genérico",
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
