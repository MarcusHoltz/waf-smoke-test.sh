# WAF Tester - Quick Security Check

Test your Web Application Firewall in less than 60 seconds. This script fires common attack payloads at your site to see what gets through.


* * *

## Quick Start

Download: [waf-smoke-test.sh](./tools/smoke-test/waf-smoke-test.sh)

```bash
# Basic test - just give it a URL
./waf-smoke-test.sh "https://example.com"

# Test a specific search parameter
./waf-smoke-test.sh "https://example.com/search?q=FUZZ"

# Save results to a file
./waf-smoke-test.sh "https://example.com" -o report.md

# Add custom headers
./waf-smoke-test.sh "https://example.com" -H "Authorization: Bearer token123"
```


* * *

## Example Output

```
🔥 WAF Smoke Test: https://example.com

#   Payload                                  Status       HTTP Code  Category
------------------------------------------------------------------------------------------
1   ' OR '1'='1                              Blocked      403        SQL Injection
2   <script>alert('xss')</script>            Blocked      403        XSS
3   ../../etc/passwd                         Blocked      403        Path Traversal
...

📊 Summary:
  Blocked: 52/60 (86.7%) - WAF actively blocked the payload
  Failed: 5/60 (8.3%) - Payload failed (page not found/error)
  Allowed: 3/60 (5.0%) - Payload was processed (potential vulnerability)

🔒 WAF Security Score: 95%
🛡️ Protection Rating: Excellent

🛡️ WAF Fingerprint(s) Detected:
  • Cloudflare

🔧 WAF Recommendations:
- SQL Injection (Obfuscated Bypass):
  • WARNING: WAF detected basic SQLi but missed obfuscated variants
  • CloudFlare: Enable advanced SQL injection detection
```


* * *

## Requirements

- `curl`, `awk`, `sed`, `grep`


* * *

## Safety Note

This script is designed for testing your own systems. Always test in staging first, and don't run this against sites you don't own or have permission to test.


* * *

Based on [realad/waf-testing](https://github.com/realad/waf-testing)
