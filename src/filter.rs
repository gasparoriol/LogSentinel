pub struct LogFilter;

impl LogFilter {

  pub fn is_suspicious(line: &str) -> bool {
    let exact_patterns = [
        "PHNjc",  // <scr
        "ID0i",   // ="
        "U0VMRUNU", // SELECT
        "RElTVElOQ1Q", // DISTINCT
        "PHNjcmlwdD", // <script (el que sale en tu log)
        "Trinity", // Trinity scanner
    ];
    let case_insensitive_patterns = [
        "../", "<?PHP", "CHMOD", "CAT /ETC", "SELECT", 
        "DROP", "OR", "ADMIN", "PASSWORD", "ETC/PASSWD", "SCRIPT", "ALERT(",
        "..\\", "..%2F..%2F", "../etc/passwd", "../etc/shadow", "../etc/hosts"
    ];

    let error_codes = ["403", "500", "502", "503", "504"];

    let nmap_patterns = [
        "NMAP",
        "NSE/",           // Nmap Scripting Engine
        "HNAP1",
        "NESSUS",         
        "ZGRAB",          // banner scanner  
        "CENSYS",         // internet scanner
    ];

    if exact_patterns.iter().any(|&p| line.contains(p)) {
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
    if case_insensitive_patterns.iter().any(|&p| upper_line.contains(p)) ||
       error_codes.iter().any(|&p| upper_line.contains(p)) || 
       nmap_patterns.iter().any(|&p| upper_line.contains(p)){
        return true;
    }

    false
  }
}
