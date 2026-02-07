pub struct LogFilter;

impl LogFilter {

  pub fn is_suspicious(line: &str) -> bool {
    let patterns = [
    "403",
    "500", 
    "502", 
    "503", 
    "504", 
    "DROP",
    "trinity",
    "SELECT",
    "OR",
    "admin", 
    "password",
    "etc/passwd"
    ];
    let upper_line = line.to_uppercase(); 
    patterns.iter().any(|pattern| upper_line.contains(pattern))
  }
}
