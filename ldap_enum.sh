#!/bin/bash

# LDAP Enumeration Script for Penetration Testing
# This script performs comprehensive LDAP enumeration using ldapsearch
# Usage: ./ldap_enum.sh <IP> <Domain> [Username] [Password]

# Color definitions
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BOLD=$(tput bold)
RESET=$(tput sgr0)

# Add new color for special findings
PURPLE=$(tput setaf 5)
ORANGE=$(tput setaf 3)
BRIGHT=$(tput bold)

# Banner function
print_banner() {
    echo "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                      LDAP ENUMERATION TOOL                       ║"
    echo "║                    Advanced Security Toolkit                     ║"
    echo "╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo
}

# Section header function
print_section() {
    echo "${BOLD}${GREEN}[+] $1 ${RESET}"
    echo "${CYAN}════════════════════════════════════════════════════════════════════${RESET}"
}

# Error function
print_error() {
    echo "${BOLD}${RED}[!] ERROR: $1 ${RESET}" >&2
    exit 1
}

# Info function
print_info() {
    echo "${BOLD}${YELLOW}[*] $1 ${RESET}"
}

# Success function
print_success() {
    echo "${BOLD}${GREEN}[✓] $1 ${RESET}"
}

# Warning function
print_warning() {
    echo "${BOLD}${YELLOW}[!] WARNING: $1 ${RESET}"
}

# Debug function - uncomment for debugging
debug() {
    echo "${MAGENTA}[DEBUG] $1 ${RESET}" >&2
}

# Check if ldapsearch is installed
check_requirements() {
    print_section "Checking Requirements"
    
    if ! command -v ldapsearch &> /dev/null; then
        print_error "ldapsearch is not installed. Please install ldap-utils package."
    fi
    
    # Check for additional tools
    local missing_tools=()
    for tool in grep awk sed cut sort uniq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_warning "Missing recommended tools: ${missing_tools[*]}"
    fi
    
    print_success "All requirements satisfied"
    echo
}

# Check arguments
if [ $# -lt 2 ] || [ $# -gt 4 ]; then
    print_banner
    print_error "Usage: $0 <IP> <Domain> [Username] [Password]"
fi

# Set variables
IP=$1
DOMAIN=$2
USERNAME=${3:-""}
PASSWORD=${4:-""}

# Build base DN from domain
BASE_DN=$(echo "$DOMAIN" | awk -F. '{for(i=1;i<=NF;i++) printf "dc=%s%s", $i, (i<NF ? "," : "")}')
OUTPUT_DIR="./ldap_enum_${IP}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${OUTPUT_DIR}/ldap_enum_${TIMESTAMP}.log"

# Build authentication options
AUTH_OPTS="-x"  # Always use simple authentication
if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
    AUTH_OPTS="${AUTH_OPTS} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\""
    print_info "Using provided credentials for authentication"
fi

# Build the common LDAP parameters
LDAP_PARAMS="-H ldap://${IP} -b \"${BASE_DN}\" -o ldif-wrap=no"

# Print information
print_banner
print_info "Target IP: ${BOLD}${WHITE}$IP${RESET}"
print_info "Domain: ${BOLD}${WHITE}$DOMAIN${RESET}"
print_info "Base DN: ${BOLD}${WHITE}$BASE_DN${RESET}"
if [ -n "$USERNAME" ]; then
    print_info "Username: ${BOLD}${WHITE}$USERNAME${RESET}"
fi
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"
if [ ! -d "$OUTPUT_DIR" ]; then
    print_error "Failed to create output directory: $OUTPUT_DIR"
fi

print_success "Created output directory: $OUTPUT_DIR"
echo

# Check requirements
check_requirements

# Function to display filtered output
display_filtered_output() {
    local file="$1"
    local type="$2"
    
    if [ ! -s "$file" ]; then
        return
    fi
    
    case "$type" in
        "users")
            echo "${BOLD}${GREEN}[+] Found Users:${RESET}"
            grep -i "sAMAccountName:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
        "computers")
            echo "${BOLD}${GREEN}[+] Found Computers:${RESET}"
            grep -i "dNSHostName:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
        "groups")
            echo "${BOLD}${GREEN}[+] Found Groups:${RESET}"
            grep -i "cn:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
        "privileged")
            echo "${BOLD}${GREEN}[+] Found Privileged Accounts:${RESET}"
            grep -i "sAMAccountName:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
        "service")
            echo "${BOLD}${GREEN}[+] Found Service Accounts:${RESET}"
            grep -i "sAMAccountName:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
        "spn")
            echo "${BOLD}${GREEN}[+] Found SPN Accounts:${RESET}"
            grep -i "sAMAccountName:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
        "pwd_desc")
            echo "${BOLD}${GREEN}[+] Found Accounts with Password Info in Description:${RESET}"
            grep -i "sAMAccountName:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
        *)
            echo "${BOLD}${GREEN}[+] Found Items:${RESET}"
            grep -i "cn:" "$file" | cut -d':' -f2- | sed 's/^ *//' | sort
            ;;
    esac
    echo
}

# Modify the run_ldapsearch function to include filtered output
run_ldapsearch() {
    local query="$1"
    local output_file="$2"
    local description="$3"
    local filter="$4"
    local type="$5"
    local ldap_cmd
    local result
    local status
    
    print_info "Querying for ${YELLOW}$description${RESET}"
    
    # Build the command differently based on whether we have credentials
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"${query}\" -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"${query}\" -o ldif-wrap=no"
    fi
    
    # Debug the command (uncomment for debugging)
    debug "Running: $ldap_cmd"
    
    # Execute the command and capture output
    if [ -z "$filter" ]; then
        result=$(eval "$ldap_cmd" 2>"${output_file}.err")
        status=$?
    else
        result=$(eval "$ldap_cmd" | grep -i "$filter" 2>"${output_file}.err")
        status=$?
    fi
    
    # Check for errors
    if [ -s "${output_file}.err" ]; then
        local error_msg=$(cat "${output_file}.err")
        print_warning "LDAP query error: $error_msg"
        rm -f "${output_file}.err"
    fi
    
    # Save the result
    echo "$result" > "$output_file"
    
    # Check if we got results
    if [ -s "$output_file" ]; then
        print_success "Results saved to: $output_file"
        echo "Query: $ldap_cmd" >> "$LOG_FILE"
        echo "Output: $output_file" >> "$LOG_FILE"
        echo >> "$LOG_FILE"
        
        # Display filtered output
        display_filtered_output "$output_file" "$type"
    else
        if [ $status -ne 0 ]; then
            print_warning "Error executing LDAP query for $description"
        else
            echo "${YELLOW}[!] No results found for $description${RESET}"
        fi
        rm -f "$output_file"
    fi
}

# Function to attempt to find the naming context if BASE_DN fails
find_naming_context() {
    print_info "Attempting to discover naming context..."
    local naming_context_cmd
    local naming_result
    local discovered_dn
    
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        naming_context_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -s base -b \"\" \"(objectClass=*)\" namingContexts"
    else
        naming_context_cmd="ldapsearch -x -H ldap://${IP} -s base -b \"\" \"(objectClass=*)\" namingContexts"
    fi
    
    debug "Running: $naming_context_cmd"
    
    naming_result=$(eval "$naming_context_cmd" 2>/dev/null)
    if [ -n "$naming_result" ]; then
        discovered_dn=$(echo "$naming_result" | grep -i "namingContexts:" | head -1 | cut -d':' -f2- | sed 's/^ *//')
        if [ -n "$discovered_dn" ]; then
            print_success "Found naming context: $discovered_dn"
            BASE_DN="$discovered_dn"
            return 0
        fi
    fi
    
    print_warning "Could not discover naming context"
    return 1
}

# Function to test for null bind (anonymous access)
test_null_bind() {
    print_info "Testing anonymous bind"
    local result
    local status
    
    result=$(ldapsearch -x -H ldap://${IP} -b "$BASE_DN" -s base "(objectClass=*)" 2>&1)
    status=$?
    
    if [ $status -eq 0 ]; then
        # Check if we got a specific error about insufficient access
        if echo "$result" | grep -q "Insufficient access"; then
            print_warning "Anonymous bind successful but access is restricted"
            print_info "This server allows anonymous access but requires authentication for most operations"
            print_info "Try running with credentials: $0 $IP $DOMAIN 'username@$DOMAIN' 'password'"
            return 0
        else
            print_success "Anonymous bind successful"
            return 0
        fi
    else
        print_warning "Anonymous bind failed"
        print_info "Error details: $result"
        return 1
    fi
}

# Function to test authentication with credentials
test_auth_bind() {
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        print_info "Testing authenticated bind"
        local result
        local status
        
        result=$(ldapsearch -x -H ldap://${IP} -D "${USERNAME}@${DOMAIN}" -w "${PASSWORD}" -b "$BASE_DN" -s base "(objectClass=*)" 2>&1)
        status=$?
        
        if [ $status -eq 0 ]; then
            print_success "Authenticated bind successful"
            return 0
        else
            print_error "Authentication failed with provided credentials"
            print_info "Error details: $result"
            print_info "Try different credentials or check the format:"
            print_info "1. Username format: username@domain"
            print_info "2. Username format: DOMAIN\\username"
            print_info "3. Username format: username"
            return 1
        fi
    else
        print_info "No credentials provided for authenticated bind"
        return 1
    fi
}

# Function to extract and highlight specific attributes
highlight_file() {
    local input_file="$1"
    local output_file="${input_file%.txt}_highlighted.txt"
    local summary_file="${input_file%.txt}_summary.txt"
    
    if [ ! -s "$input_file" ]; then
        return
    fi
    
    # Skip if the file is already a highlighted or summary file
    if [[ "$input_file" == *"_highlighted.txt" ]] || [[ "$input_file" == *"_summary.txt" ]]; then
        return
    fi
    
    print_info "Processing ${input_file##*/}"
    
    # Create a highlighted version
    if ! cat "$input_file" | sed -E \
        -e "s/^(dn:.*)/$(printf "${BOLD}${GREEN}")\\1$(printf "${RESET}")/g" \
        -e "s/^(cn:.*)/$(printf "${BOLD}${CYAN}")\\1$(printf "${RESET}")/g" \
        -e "s/^(sAMAccountName:.*)/$(printf "${BOLD}${YELLOW}")\\1$(printf "${RESET}")/g" \
        -e "s/^(objectSid:.*)/$(printf "${BOLD}${MAGENTA}")\\1$(printf "${RESET}")/g" \
        -e "s/^(description:.*)/$(printf "${BOLD}${RED}")\\1$(printf "${RESET}")/g" \
        -e "s/^(userPrincipalName:.*)/$(printf "${BOLD}${BLUE}")\\1$(printf "${RESET}")/g" \
        -e "s/^(member:.*)/$(printf "${BOLD}${CYAN}")\\1$(printf "${RESET}")/g" \
        -e "s/^(memberOf:.*)/$(printf "${BOLD}${CYAN}")\\1$(printf "${RESET}")/g" \
        -e "s/^(objectClass:.*)/$(printf "${WHITE}")\\1$(printf "${RESET}")/g" \
        > "$output_file"; then
        print_warning "Failed to create highlighted version of $input_file"
        return
    fi
    
    # Create a summary with only important attributes
    if ! grep -E "^dn:|sAMAccountName:|cn:|description:|userPrincipalName:|objectSid:|member:|memberOf:|pwdLastSet:|lastLogon:" "$input_file" | \
        awk '/^dn:/ {if(NR>1) print "----------------------------------------"}1' > "$summary_file"; then
        print_warning "Failed to create summary version of $input_file"
        return
    fi
    
    print_success "Created highlighted file: ${output_file##*/}"
    print_success "Created summary file: ${summary_file##*/}"
}

# Function to search for interesting attributes
search_interesting_attributes() {
    print_section "Searching for Interesting Attributes"
    
    # Common standard attributes that we know about
    local common_attrs=(
        "objectClass"
        "cn"
        "sAMAccountName"
        "userPrincipalName"
        "distinguishedName"
        "instanceType"
        "whenCreated"
        "whenChanged"
        "displayName"
        "uSNCreated"
        "memberOf"
        "uSNChanged"
        "name"
        "objectGUID"
        "userAccountControl"
        "badPwdCount"
        "codePage"
        "countryCode"
        "badPasswordTime"
        "lastLogoff"
        "lastLogon"
        "pwdLastSet"
        "primaryGroupID"
        "objectSid"
        "accountExpires"
        "logonCount"
        "sAMAccountType"
        "userParameters"
        "objectCategory"
        "dSCorePropagationData"
        "lastLogonTimestamp"
        "mail"
        "description"
        "member"
        "maxPwdAge"
        "minPwdAge"
        "minPwdLength"
        "pwdProperties"
        "pwdHistoryLength"
        "lockoutThreshold"
        "lockoutDuration"
        "lockoutObservationWindow"
        "gPLink"
        "gPOptions"
        "whenChanged"
        "whenCreated"
        "nTSecurityDescriptor"
        "servicePrincipalName"
        "dNSHostName"
        "operatingSystem"
        "operatingSystemVersion"
        "operatingSystemServicePack"
        "serverReference"
        "serverReferenceBL"
        "msDS-AllowedToDelegateTo"
        "msDS-AllowedToActOnBehalfOfOtherIdentity"
        "msDS-User-Account-Control-Computed"
        "msDS-UserPasswordExpiryTimeComputed"
        "msDS-LastSuccessfulInteractiveLogonTime"
        "msDS-LastFailedInteractiveLogonTime"
        "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon"
        "wellKnownObjects"
        "fSMORoleOwner"
        "rIDManagerReference"
        "subRefs"
        "otherWellKnownObjects"
        "masteredBy"
        "msDs-masteredBy"
        "msDS-IsDomainFor"
        "rIDSetReferences"
        "msDFSR-ComputerReferenceBL"
        "msDFSR-ComputerReference"
        "msDFSR-MemberReferenceBL"
        "msDFSR-MemberReference"
        "dnsRecord"
        "ref"
    )
    
    # System attributes that should be filtered out
    local system_attrs=(
        "ipsec.*"
        "msDFSR.*"
        "dnsRecord"
        "ref"
        "wellKnownObjects"
        "fSMORoleOwner"
        "rIDManagerReference"
        "subRefs"
        "otherWellKnownObjects"
        "masteredBy"
        "msDs-masteredBy"
        "msDS-IsDomainFor"
        "rIDSetReferences"
    )
    
    local interesting_attrs=(
        "password"
        "pass"
        "pwd"
        "Pwd"
        "badPwdCount"
        "maxPwdAge"
        "minPwdAge"
        "minPwdLength"
        "userAccountControl"
        "whenCreated"
        "lastLogon"
        "lockoutTime"
        "pwdLastSet"
        "pwdChangedTime"
        "memberOf"
        "description"
        "sAMAccountName"
        "cn"
    )
    
    local output_file="${OUTPUT_DIR}/interesting_attributes.txt"
    local custom_attrs_file="${OUTPUT_DIR}/custom_attributes.txt"
    local ldap_cmd
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=*)\" -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=*)\" -o ldif-wrap=no"
    fi
    
    # Execute the command and filter for interesting attributes
    eval "$ldap_cmd" | grep -i -E "$(printf "%s|" "${interesting_attrs[@]}" | sed 's/|$//')" > "$output_file"
    
    # Capture all attributes and filter out common ones
    eval "$ldap_cmd" | grep -i "^[a-zA-Z0-9-]*:" | cut -d':' -f1 | sort -u | while read -r attr; do
        # Skip if it's a common attribute
        if ! printf "%s\n" "${common_attrs[@]}" | grep -q -i "^$attr$"; then
            # Skip if it matches any system attribute pattern
            skip=0
            for pattern in "${system_attrs[@]}"; do
                if [[ "$attr" =~ $pattern ]]; then
                    skip=1
                    break
                fi
            done
            if [ $skip -eq 0 ]; then
                echo "$attr" >> "$custom_attrs_file"
            fi
        fi
    done
    
    if [ -s "$output_file" ]; then
        print_success "Found interesting attributes. Displaying results..."
        echo
        
        # Process the file to extract and organize information
        local temp_file=$(mktemp -p "${OUTPUT_DIR}")
        local seen_entries=$(mktemp -p "${OUTPUT_DIR}")
        local current_dn=""
        local current_name=""
        local current_sam=""
        local current_cn=""
        
        # First pass: Create a mapping of DNs to names and sAMAccountNames
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                current_name=$(echo "$current_dn" | grep -o "CN=[^,]*" | sed 's/CN=//')
                current_sam=""
                current_cn=""
            elif [[ $line =~ ^sAMAccountName: ]]; then
                current_sam=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
            elif [[ $line =~ ^cn: ]]; then
                current_cn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
            fi
            echo "$current_dn|$current_name|$current_sam|$current_cn" >> "$temp_file"
        done < "$output_file"
        
        # Function to get display name
        get_display_name() {
            local dn="$1"
            local info=$(grep "$dn" "$temp_file" | head -1)
            local name=$(echo "$info" | cut -d'|' -f2)
            local sam=$(echo "$info" | cut -d'|' -f3)
            local cn=$(echo "$info" | cut -d'|' -f4)
            if [ -n "$sam" ]; then
                echo "$sam"
            elif [ -n "$cn" ]; then
                echo "$cn"
            else
                echo "$name"
            fi
        }
        
        # Display custom attributes if found
        if [ -s "$custom_attrs_file" ]; then
            echo "${BOLD}${CYAN}[+] Custom/Non-Standard Attributes Found:${RESET}"
            echo "Account Name                Custom Attribute            Value"
            echo "----------------------------------------------------------------"
            while read -r line; do
                if [[ $line =~ ^dn: ]]; then
                    current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                    display_name=$(get_display_name "$current_dn")
                elif [[ $line =~ ^[a-zA-Z0-9-]*: ]]; then
                    attr=$(echo "$line" | cut -d':' -f1)
                    if grep -q -i "^$attr$" "$custom_attrs_file"; then
                        value=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                        entry_key="$display_name|$attr|$value"
                        if ! grep -q "^$entry_key$" "$seen_entries" 2>/dev/null; then
                            printf "%-30s %-25s %s\n" "$display_name" "$attr" "$value"
                            echo "$entry_key" >> "$seen_entries"
                        fi
                    fi
                fi
            done < "$output_file"
            echo
        fi
        
        # Display password-related attributes with usernames
        echo "${BOLD}${RED}[+] Password Related Attributes:${RESET}"
        echo "Account Name                Attribute                Value"
        echo "----------------------------------------------------------------"
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                display_name=$(get_display_name "$current_dn")
            elif [[ $line =~ ^(badPwdCount|maxPwdAge|minPwdAge|minPwdLength|pwdLastSet|pwdProperties): ]]; then
                attr=$(echo "$line" | cut -d':' -f1)
                value=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                entry_key="$display_name|$attr|$value"
                if ! grep -q "^$entry_key$" "$seen_entries" 2>/dev/null; then
                    printf "%-30s %-25s %s\n" "$display_name" "$attr" "$value"
                    echo "$entry_key" >> "$seen_entries"
                fi
            fi
        done < "$output_file"
        echo
        
        # Display account control attributes with usernames
        echo "${BOLD}${YELLOW}[+] Account Control Attributes:${RESET}"
        echo "Account Name                Attribute                Value"
        echo "----------------------------------------------------------------"
        > "$seen_entries"  # Clear the seen entries file
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                display_name=$(get_display_name "$current_dn")
            elif [[ $line =~ ^userAccountControl: ]]; then
                attr=$(echo "$line" | cut -d':' -f1)
                value=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                entry_key="$display_name|$attr|$value"
                if ! grep -q "^$entry_key$" "$seen_entries" 2>/dev/null; then
                    printf "%-30s %-25s %s\n" "$display_name" "$attr" "$value"
                    echo "$entry_key" >> "$seen_entries"
                fi
            fi
        done < "$output_file"
        echo
        
        # Display time-related attributes with usernames
        echo "${BOLD}${BLUE}[+] Time-Related Attributes:${RESET}"
        echo "Account Name                Attribute                Value"
        echo "----------------------------------------------------------------"
        > "$seen_entries"  # Clear the seen entries file
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                display_name=$(get_display_name "$current_dn")
            elif [[ $line =~ ^(lastLogon|lastLogonTimestamp|pwdLastSet|whenCreated): ]]; then
                attr=$(echo "$line" | cut -d':' -f1)
                value=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                entry_key="$display_name|$attr|$value"
                if ! grep -q "^$entry_key$" "$seen_entries" 2>/dev/null; then
                    printf "%-30s %-25s %s\n" "$display_name" "$attr" "$value"
                    echo "$entry_key" >> "$seen_entries"
                fi
            fi
        done < "$output_file"
        echo
        
        # Display group memberships with usernames
        echo "${BOLD}${GREEN}[+] Group Memberships:${RESET}"
        echo "Account Name                Group Membership"
        echo "----------------------------------------------------------------"
        > "$seen_entries"  # Clear the seen entries file
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                display_name=$(get_display_name "$current_dn")
            elif [[ $line =~ ^memberOf: ]]; then
                group=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                entry_key="$display_name|$group"
                if ! grep -q "^$entry_key$" "$seen_entries" 2>/dev/null; then
                    printf "%-30s %s\n" "$display_name" "$group"
                    echo "$entry_key" >> "$seen_entries"
                fi
            fi
        done < "$output_file"
        echo
        
        # Display interesting descriptions with usernames
        echo "${BOLD}${MAGENTA}[+] Interesting Descriptions:${RESET}"
        echo "Account Name                Description"
        echo "----------------------------------------------------------------"
        > "$seen_entries"  # Clear the seen entries file
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                display_name=$(get_display_name "$current_dn")
            elif [[ $line =~ ^description: ]]; then
                desc=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                entry_key="$display_name|$desc"
                if ! grep -q "^$entry_key$" "$seen_entries" 2>/dev/null; then
                    printf "%-30s %s\n" "$display_name" "$desc"
                    echo "$entry_key" >> "$seen_entries"
                fi
            fi
        done < "$output_file"
        echo
        
        rm -f "$temp_file" "$seen_entries"
        print_success "Full results saved to: $output_file"
        if [ -s "$custom_attrs_file" ]; then
            print_success "Custom attributes saved to: $custom_attrs_file"
        fi
    else
        print_warning "No interesting attributes found"
    fi
}

# Function to filter buzzworthy findings
filter_buzzworthy() {
    local input_file="$1"
    local output_file="${OUTPUT_DIR}/buzzworthy_findings.txt"
    local buzz_count=0
    
    print_section "Analyzing Buzzworthy Findings"
    
    # Create or clear the buzzworthy file
    echo "${BOLD}${RED}BUZZWORTHY FINDINGS${RESET}" > "$output_file"
    echo "Generated on: $(date)" >> "$output_file"
    echo "===============================================================" >> "$output_file"
    echo >> "$output_file"
    
    # Check for password in descriptions
    if grep -i -E "password|pwd|cred" "$input_file" > /dev/null; then
        echo "${BOLD}${RED}[!] PASSWORDS IN DESCRIPTIONS${RESET}" >> "$output_file"
        grep -i -E "password|pwd|cred" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for legacy passwords
    if grep -i "cascadeLegacyPwd" "$input_file" > /dev/null; then
        echo "${BOLD}${RED}[!] LEGACY PASSWORDS FOUND${RESET}" >> "$output_file"
        grep -i "cascadeLegacyPwd" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for service accounts
    if grep -i -E "svc|service|backup" "$input_file" > /dev/null; then
        echo "${BOLD}${YELLOW}[!] SERVICE ACCOUNTS${RESET}" >> "$output_file"
        grep -i -E "svc|service|backup" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for admin/privileged groups
    if grep -i -E "admin|privileged|domain admins|enterprise admins|IT" "$input_file" > /dev/null; then
        echo "${BOLD}${YELLOW}[!] PRIVILEGED GROUPS${RESET}" >> "$output_file"
        grep -i -E "admin|privileged|domain admins|enterprise admins|IT" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for interesting file shares
    if grep -i -E "\\\\|share|unc|audit|data" "$input_file" > /dev/null; then
        echo "${BOLD}${BLUE}[!] INTERESTING FILE SHARES${RESET}" >> "$output_file"
        grep -i -E "\\\\|share|unc|audit|data" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for SPN accounts (Kerberoasting)
    if grep -i "servicePrincipalName" "$input_file" > /dev/null; then
        echo "${BOLD}${MAGENTA}[!] KERBEROASTING CANDIDATES${RESET}" >> "$output_file"
        grep -i "servicePrincipalName" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for disabled accounts
    if grep -i "userAccountControl:.*514" "$input_file" > /dev/null; then
        echo "${BOLD}${CYAN}[!] DISABLED ACCOUNTS${RESET}" >> "$output_file"
        grep -i "userAccountControl:.*514" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for never expiring passwords
    if grep -i "pwdLastSet:.*0" "$input_file" > /dev/null; then
        echo "${BOLD}${CYAN}[!] NEVER EXPIRING PASSWORDS${RESET}" >> "$output_file"
        grep -i "pwdLastSet:.*0" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for Remote Management access
    if grep -i -E "Remote Management|WinRM" "$input_file" > /dev/null; then
        echo "${BOLD}${GREEN}[!] REMOTE MANAGEMENT ACCESS${RESET}" >> "$output_file"
        grep -i -E "Remote Management|WinRM" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for backup related information
    if grep -i -E "backup|BCKUPKEY" "$input_file" > /dev/null; then
        echo "${BOLD}${MAGENTA}[!] BACKUP RELATED INFORMATION${RESET}" >> "$output_file"
        grep -i -E "backup|BCKUPKEY" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    # Check for interesting group memberships
    if grep -i -E "memberOf:.*IT|memberOf:.*Remote Management|memberOf:.*Audit" "$input_file" > /dev/null; then
        echo "${BOLD}${YELLOW}[!] INTERESTING GROUP MEMBERSHIPS${RESET}" >> "$output_file"
        grep -i -E "memberOf:.*IT|memberOf:.*Remote Management|memberOf:.*Audit" "$input_file" | while read -r line; do
            echo "$line" >> "$output_file"
            ((buzz_count++))
        done
        echo >> "$output_file"
    fi
    
    if [ $buzz_count -gt 0 ]; then
        print_success "Found $buzz_count buzzworthy items"
        print_success "Buzzworthy findings saved to: $output_file"
        highlight_file "$output_file"
    else
        print_info "No buzzworthy findings detected"
        rm -f "$output_file"
    fi
}

# Function to check for password policy
check_password_policy() {
    print_section "Checking Password Policy"
    local output_file="${OUTPUT_DIR}/password_policy.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=domainDNS)\" minPwdLength maxPwdAge pwdHistoryLength pwdProperties lockoutThreshold lockoutDuration"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=domainDNS)\" minPwdLength maxPwdAge pwdHistoryLength pwdProperties lockoutThreshold lockoutDuration"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "Password policy information saved to: $output_file"
        echo "${BOLD}${PURPLE}[+] Password Policy Details:${RESET}"
        grep -E "minPwdLength|maxPwdAge|pwdHistoryLength|pwdProperties|lockoutThreshold|lockoutDuration" "$output_file" | while read -r line; do
            echo "$line"
        done
    else
        print_warning "Could not retrieve password policy information"
    fi
}

# Function to check for interesting ACLs
check_interesting_acls() {
    print_section "Checking Interesting ACLs"
    local output_file="${OUTPUT_DIR}/interesting_acls.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=*)\" nTSecurityDescriptor"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=*)\" nTSecurityDescriptor"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "ACL information saved to: $output_file"
        echo "${BOLD}${ORANGE}[+] Interesting ACLs Found:${RESET}"
        grep -i "nTSecurityDescriptor" "$output_file" | while read -r line; do
            echo "$line"
        done
    else
        print_warning "Could not retrieve ACL information"
    fi
}

# Function to check for delegation
check_delegation() {
    print_section "Checking for Delegation"
    local output_file="${OUTPUT_DIR}/delegation.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))\""
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))\""
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "Delegation information saved to: $output_file"
        echo "${BOLD}${RED}[+] Delegation Found:${RESET}"
        grep -i "msDS-AllowedToDelegateTo\|msDS-AllowedToActOnBehalfOfOtherIdentity" "$output_file" | while read -r line; do
            echo "$line"
        done
    else
        print_info "No delegation found"
    fi
}

# Function to check for GPOs
check_gpos() {
    print_section "Checking Group Policy Objects"
    local output_file="${OUTPUT_DIR}/gpos_detailed.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" displayName gPCFileSysPath"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" displayName gPCFileSysPath"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "GPO information saved to: $output_file"
        echo "${BOLD}${BLUE}[+] GPOs Found:${RESET}"
        grep -i "displayName\|gPCFileSysPath" "$output_file" | while read -r line; do
            echo "$line"
        done
    else
        print_warning "Could not retrieve GPO information"
    fi
}

# Function to check for interesting shares
check_shares() {
    print_section "Checking for Interesting Shares"
    local output_file="${OUTPUT_DIR}/shares.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(|(objectClass=volume)(objectClass=share))\" cn description"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(|(objectClass=volume)(objectClass=share))\" cn description"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "Share information saved to: $output_file"
        echo "${BOLD}${GREEN}[+] Shares Found:${RESET}"
        grep -i "cn\|description" "$output_file" | while read -r line; do
            echo "$line"
        done
    else
        print_info "No shares found"
    fi
}

# Function to check for interesting SPNs
check_spns() {
    print_section "Checking for Service Principal Names"
    local output_file="${OUTPUT_DIR}/spns_detailed.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(&(objectClass=user)(servicePrincipalName=*))\" sAMAccountName servicePrincipalName"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(&(objectClass=user)(servicePrincipalName=*))\" sAMAccountName servicePrincipalName"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "SPN information saved to: $output_file"
        echo "${BOLD}${MAGENTA}[+] SPNs Found:${RESET}"
        grep -i "sAMAccountName\|servicePrincipalName" "$output_file" | while read -r line; do
            echo "$line"
        done
    else
        print_info "No SPNs found"
    fi
}

# Function to check for interesting attributes in descriptions
check_descriptions() {
    print_section "Checking for Interesting Descriptions"
    local output_file="${OUTPUT_DIR}/descriptions_detailed.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(description=*)\" sAMAccountName description"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(description=*)\" sAMAccountName description"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "Description information saved to: $output_file"
        echo "${BOLD}${YELLOW}[+] Interesting Descriptions Found:${RESET}"
        grep -i "sAMAccountName\|description" "$output_file" | while read -r line; do
            echo "$line"
        done
    else
        print_info "No interesting descriptions found"
    fi
}

# Function to test common credentials
test_common_credentials() {
    print_section "Testing Common Credentials"
    local output_file="${OUTPUT_DIR}/credential_test.txt"
    
    # Common usernames to try
    local common_usernames=(
        "administrator"
        "admin"
        "guest"
        "test"
        "user"
        "support"
        "helpdesk"
        "backup"
        "sql"
        "oracle"
        "mysql"
        "postgres"
        "root"
    )
    
    # Common passwords to try
    local common_passwords=(
        ""
        "password"
        "Password123"
        "admin"
        "administrator"
        "welcome"
        "welcome123"
        "letmein"
        "changeme"
        "P@ssw0rd"
        "P@ssword123"
        "Qwerty123"
        "Qwerty!@#"
        "Admin123"
        "Admin!@#"
    )
    
    # Test each combination
    for username in "${common_usernames[@]}"; do
        # Try different username formats
        local username_formats=(
            "$username"
            "$username@$DOMAIN"
            "$(echo "$DOMAIN" | cut -d. -f1)\\$username"
        )
        
        for username_format in "${username_formats[@]}"; do
            for password in "${common_passwords[@]}"; do
                print_info "Trying: $username_format with password: $password"
                
                # Build the command
                local ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"$username_format\" -w \"$password\" -b \"${BASE_DN}\" \"(objectClass=*)\" -o ldif-wrap=no"
                
                # Execute the command
                local result=$(eval "$ldap_cmd" 2>&1)
                local status=$?
                
                # Check if authentication was successful
                if [ $status -eq 0 ] && ! echo "$result" | grep -q "Invalid credentials"; then
                    print_success "Successful authentication with: $username_format:$password"
                    echo "Successful authentication with: $username_format:$password" >> "$output_file"
                    return 0
                fi
            done
        done
    done
    
    print_warning "No successful authentication found with common credentials"
    return 1
}

# Function to check for password policy details
check_password_policy_details() {
    print_section "Checking Password Policy Details"
    local output_file="${OUTPUT_DIR}/password_policy_details.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=domainDNS)\" minPwdLength maxPwdAge pwdHistoryLength pwdProperties lockoutThreshold lockoutDuration minPwdAge"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=domainDNS)\" minPwdLength maxPwdAge pwdHistoryLength pwdProperties lockoutThreshold lockoutDuration minPwdAge"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "Password policy details saved to: $output_file"
        echo "${BOLD}${PURPLE}[+] Password Policy Details:${RESET}"
        
        # Parse and display password policy in a more readable format
        local min_length=$(grep "minPwdLength:" "$output_file" | cut -d':' -f2 | sed 's/^ *//')
        local max_age=$(grep "maxPwdAge:" "$output_file" | cut -d':' -f2 | sed 's/^ *//')
        local min_age=$(grep "minPwdAge:" "$output_file" | cut -d':' -f2 | sed 's/^ *//')
        local history=$(grep "pwdHistoryLength:" "$output_file" | cut -d':' -f2 | sed 's/^ *//')
        local properties=$(grep "pwdProperties:" "$output_file" | cut -d':' -f2 | sed 's/^ *//')
        local lockout_threshold=$(grep "lockoutThreshold:" "$output_file" | cut -d':' -f2 | sed 's/^ *//')
        local lockout_duration=$(grep "lockoutDuration:" "$output_file" | cut -d':' -f2 | sed 's/^ *//')
        
        echo "Minimum Password Length: $min_length"
        echo "Maximum Password Age: $max_age"
        echo "Minimum Password Age: $min_age"
        echo "Password History Length: $history"
        echo "Password Properties: $properties"
        echo "Account Lockout Threshold: $lockout_threshold"
        echo "Account Lockout Duration: $lockout_duration"
        
        # Add password policy analysis
        echo "${BOLD}${YELLOW}[+] Password Policy Analysis:${RESET}"
        if [ -n "$min_length" ] && [ "$min_length" -lt 8 ]; then
            echo "WARNING: Minimum password length is less than 8 characters"
        fi
        if [ -n "$history" ] && [ "$history" -eq 0 ]; then
            echo "WARNING: Password history is not enforced"
        fi
        if [ -n "$lockout_threshold" ] && [ "$lockout_threshold" -eq 0 ]; then
            echo "WARNING: Account lockout is not enabled"
        fi
    else
        print_warning "Could not retrieve password policy details"
    fi
}

# Function to check for interesting attributes in user objects
check_user_attributes() {
    print_section "Checking User Attributes"
    local output_file="${OUTPUT_DIR}/user_attributes.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=user)\" sAMAccountName userPrincipalName description memberOf lastLogon pwdLastSet userAccountControl"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=user)\" sAMAccountName userPrincipalName description memberOf lastLogon pwdLastSet userAccountControl"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    if [ -s "$output_file" ]; then
        print_success "User attributes saved to: $output_file"
        echo "${BOLD}${GREEN}[+] User Attributes Found:${RESET}"
        
        # Parse and display user attributes in a more readable format
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                echo
                echo "User: $(echo "$line" | cut -d':' -f2- | sed 's/^ *//')"
            elif [[ $line =~ ^sAMAccountName: ]]; then
                echo "Username: $(echo "$line" | cut -d':' -f2- | sed 's/^ *//')"
            elif [[ $line =~ ^description: ]]; then
                echo "Description: $(echo "$line" | cut -d':' -f2- | sed 's/^ *//')"
            elif [[ $line =~ ^memberOf: ]]; then
                echo "Member of: $(echo "$line" | cut -d':' -f2- | sed 's/^ *//')"
            elif [[ $line =~ ^userAccountControl: ]]; then
                local uac=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                echo "Account Control: $uac"
                if [ $((uac & 2)) -ne 0 ]; then
                    echo "WARNING: Account is disabled"
                fi
                if [ $((uac & 16)) -ne 0 ]; then
                    echo "WARNING: Account password does not expire"
                fi
            fi
        done < "$output_file"
    else
        print_warning "Could not retrieve user attributes"
    fi
}

# Function to scan for custom/non-standard attributes
scan_custom_attributes() {
    print_section "Scanning for Custom/Non-Standard Attributes"
    local output_file="${OUTPUT_DIR}/custom_attributes.txt"
    local detailed_file="${OUTPUT_DIR}/custom_attributes_detailed.txt"
    local sensitive_file="${OUTPUT_DIR}/sensitive_custom_attributes.txt"
    
    # Common standard attributes that we know about
    local common_attrs=(
        "objectClass"
        "cn"
        "sAMAccountName"
        "userPrincipalName"
        "distinguishedName"
        "instanceType"
        "whenCreated"
        "whenChanged"
        "displayName"
        "uSNCreated"
        "memberOf"
        "uSNChanged"
        "name"
        "objectGUID"
        "userAccountControl"
        "badPwdCount"
        "codePage"
        "countryCode"
        "badPasswordTime"
        "lastLogoff"
        "lastLogon"
        "pwdLastSet"
        "primaryGroupID"
        "objectSid"
        "accountExpires"
        "logonCount"
        "sAMAccountType"
        "userParameters"
        "objectCategory"
        "dSCorePropagationData"
        "lastLogonTimestamp"
        "mail"
        "description"
        "member"
        "maxPwdAge"
        "minPwdAge"
        "minPwdLength"
        "pwdProperties"
        "pwdHistoryLength"
        "lockoutThreshold"
        "lockoutDuration"
        "lockoutObservationWindow"
        "gPLink"
        "gPOptions"
        "whenChanged"
        "whenCreated"
        "nTSecurityDescriptor"
        "servicePrincipalName"
        "dNSHostName"
        "operatingSystem"
        "operatingSystemVersion"
        "operatingSystemServicePack"
        "serverReference"
        "serverReferenceBL"
        "msDS-AllowedToDelegateTo"
        "msDS-AllowedToActOnBehalfOfOtherIdentity"
        "msDS-User-Account-Control-Computed"
        "msDS-UserPasswordExpiryTimeComputed"
        "msDS-LastSuccessfulInteractiveLogonTime"
        "msDS-LastFailedInteractiveLogonTime"
        "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon"
    )
    
    # Patterns to identify potentially sensitive attributes
    local sensitive_patterns=(
        "password"
        "pwd"
        "cred"
        "secret"
        "key"
        "token"
        "hash"
        "cert"
        "ssh"
        "private"
        "backup"
        "admin"
        "root"
        "service"
        "svc"
        "api"
        "auth"
        "login"
        "access"
        "privilege"
    )
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=*)\" -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=*)\" -o ldif-wrap=no"
    fi
    
    # Execute the command and capture all attributes
    print_info "Collecting all attributes from LDAP directory..."
    local all_attrs=$(eval "$ldap_cmd" | grep -i "^[a-zA-Z0-9-]*:" | cut -d':' -f1 | sort -u)
    
    # Filter out common attributes and find custom ones
    print_info "Analyzing attributes..."
    local custom_attrs=()
    local sensitive_attrs=()
    
    while read -r attr; do
        # Skip if it's a common attribute
        if ! printf "%s\n" "${common_attrs[@]}" | grep -q -i "^$attr$"; then
            custom_attrs+=("$attr")
            
            # Check for sensitive patterns
            for pattern in "${sensitive_patterns[@]}"; do
                if [[ "$attr" =~ $pattern ]]; then
                    sensitive_attrs+=("$attr")
                    break
                fi
            done
        fi
    done <<< "$all_attrs"
    
    # Save custom attributes list
    printf "%s\n" "${custom_attrs[@]}" > "$output_file"
    
    if [ ${#custom_attrs[@]} -gt 0 ]; then
        print_success "Found ${#custom_attrs[@]} custom attributes"
        echo "${BOLD}${PURPLE}[+] Custom Attributes Found:${RESET}"
        printf "%s\n" "${custom_attrs[@]}"
        
        # Check for sensitive attributes
        if [ ${#sensitive_attrs[@]} -gt 0 ]; then
            print_warning "Found ${#sensitive_attrs[@]} potentially sensitive custom attributes"
            echo "${BOLD}${RED}[!] Potentially Sensitive Custom Attributes:${RESET}"
            printf "%s\n" "${sensitive_attrs[@]}"
            printf "%s\n" "${sensitive_attrs[@]}" > "$sensitive_file"
        fi
        
        # Now get detailed information about objects with custom attributes
        print_info "Collecting detailed information about objects with custom attributes..."
        
        # Build a filter for objects with custom attributes
        local filter="(|"
        for attr in "${custom_attrs[@]}"; do
            filter="${filter}(${attr}=*)"
        done
        filter="${filter})"
        
        # Execute detailed search
        if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
            ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"${filter}\" -o ldif-wrap=no"
        else
            ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"${filter}\" -o ldif-wrap=no"
        fi
        
        eval "$ldap_cmd" > "$detailed_file"
        
        if [ -s "$detailed_file" ]; then
            print_success "Detailed information saved to: $detailed_file"
            echo "${BOLD}${GREEN}[+] Objects with Custom Attributes:${RESET}"
            
            # Process and display the detailed information
            local current_dn=""
            local current_attrs=()
            local current_sensitive_attrs=()
            
            while read -r line; do
                if [[ $line =~ ^dn: ]]; then
                    if [ -n "$current_dn" ]; then
                        echo
                        echo "Object: $current_dn"
                        if [ ${#current_attrs[@]} -gt 0 ]; then
                            echo "Custom Attributes:"
                            printf "  %s\n" "${current_attrs[@]}"
                        fi
                        if [ ${#current_sensitive_attrs[@]} -gt 0 ]; then
                            echo "${BOLD}${RED}Potentially Sensitive Attributes:${RESET}"
                            printf "  %s\n" "${current_sensitive_attrs[@]}"
                        fi
                        echo "----------------------------------------"
                    fi
                    current_dn=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                    current_attrs=()
                    current_sensitive_attrs=()
                elif [[ $line =~ ^[a-zA-Z0-9-]*: ]]; then
                    attr=$(echo "$line" | cut -d':' -f1)
                    if printf "%s\n" "${custom_attrs[@]}" | grep -q -i "^$attr$"; then
                        current_attrs+=("$line")
                        if printf "%s\n" "${sensitive_attrs[@]}" | grep -q -i "^$attr$"; then
                            current_sensitive_attrs+=("$line")
                        fi
                    fi
                fi
            done < "$detailed_file"
            
            # Print the last object
            if [ -n "$current_dn" ]; then
                echo
                echo "Object: $current_dn"
                if [ ${#current_attrs[@]} -gt 0 ]; then
                    echo "Custom Attributes:"
                    printf "  %s\n" "${current_attrs[@]}"
                fi
                if [ ${#current_sensitive_attrs[@]} -gt 0 ]; then
                    echo "${BOLD}${RED}Potentially Sensitive Attributes:${RESET}"
                    printf "  %s\n" "${current_sensitive_attrs[@]}"
                fi
            fi
            
            # Create a highlighted version
            highlight_file "$detailed_file"
            
            # Add sensitive attributes to buzzworthy findings
            if [ -s "$sensitive_file" ]; then
                echo "${BOLD}${RED}[!] SENSITIVE CUSTOM ATTRIBUTES${RESET}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
                echo "Generated on: $(date)" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
                echo "===============================================================" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
                cat "$sensitive_file" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
                echo >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            fi
        fi
    else
        print_info "No custom attributes found"
        rm -f "$output_file" "$detailed_file" "$sensitive_file"
    fi
}

# Function to analyze Kerberos settings and vulnerabilities
analyze_kerberos() {
    print_section "Analyzing Kerberos Settings and Vulnerabilities"
    local output_file="${OUTPUT_DIR}/kerberos_analysis.txt"
    local vulnerable_file="${OUTPUT_DIR}/kerberos_vulnerabilities.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))\" sAMAccountName userAccountControl servicePrincipalName msDS-AllowedToDelegateTo msDS-AllowedToActOnBehalfOfOtherIdentity -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))\" sAMAccountName userAccountControl servicePrincipalName msDS-AllowedToDelegateTo msDS-AllowedToActOnBehalfOfOtherIdentity -o ldif-wrap=no"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file"
    
    if [ -s "$output_file" ]; then
        print_success "Kerberos analysis saved to: $output_file"
        echo "${BOLD}${PURPLE}[+] Kerberos Analysis:${RESET}"
        
        # Initialize counters
        local asrep_roastable=0
        local unconstrained_delegation=0
        local constrained_delegation=0
        local resource_based_delegation=0
        
        # Process the output
        local current_user=""
        local current_spns=()
        local current_delegation=""
        
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                if [ -n "$current_user" ]; then
                    echo
                    echo "User: $current_user"
                    if [ ${#current_spns[@]} -gt 0 ]; then
                        echo "SPNs:"
                        printf "  %s\n" "${current_spns[@]}"
                    fi
                    if [ -n "$current_delegation" ]; then
                        echo "Delegation: $current_delegation"
                    fi
                    echo "----------------------------------------"
                fi
                current_user=""
                current_spns=()
                current_delegation=""
            elif [[ $line =~ ^sAMAccountName: ]]; then
                current_user=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
            elif [[ $line =~ ^servicePrincipalName: ]]; then
                current_spns+=("$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')")
            elif [[ $line =~ ^msDS-AllowedToDelegateTo: ]]; then
                current_delegation="Constrained Delegation"
                ((constrained_delegation++))
            elif [[ $line =~ ^msDS-AllowedToActOnBehalfOfOtherIdentity: ]]; then
                current_delegation="Resource-Based Delegation"
                ((resource_based_delegation++))
            elif [[ $line =~ ^userAccountControl: ]]; then
                local uac=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                if [ $((uac & 4194304)) -ne 0 ]; then
                    ((asrep_roastable++))
                    echo "${BOLD}${RED}[!] AS-REP Roastable Account Found: $current_user${RESET}"
                    echo "AS-REP Roastable Account: $current_user" >> "$vulnerable_file"
                fi
            fi
        done < "$output_file"
        
        # Print the last user
        if [ -n "$current_user" ]; then
            echo
            echo "User: $current_user"
            if [ ${#current_spns[@]} -gt 0 ]; then
                echo "SPNs:"
                printf "  %s\n" "${current_spns[@]}"
            fi
            if [ -n "$current_delegation" ]; then
                echo "Delegation: $current_delegation"
            fi
        fi
        
        # Print summary
        echo
        echo "${BOLD}${YELLOW}[+] Kerberos Vulnerability Summary:${RESET}"
        echo "AS-REP Roastable Accounts: $asrep_roastable"
        echo "Unconstrained Delegation: $unconstrained_delegation"
        echo "Constrained Delegation: $constrained_delegation"
        echo "Resource-Based Delegation: $resource_based_delegation"
        
        # Add to buzzworthy findings if vulnerabilities found
        if [ $asrep_roastable -gt 0 ] || [ $unconstrained_delegation -gt 0 ] || [ $constrained_delegation -gt 0 ] || [ $resource_based_delegation -gt 0 ]; then
            echo "${BOLD}${RED}[!] KERBEROS VULNERABILITIES${RESET}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Generated on: $(date)" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "===============================================================" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "AS-REP Roastable Accounts: $asrep_roastable" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Unconstrained Delegation: $unconstrained_delegation" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Constrained Delegation: $constrained_delegation" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Resource-Based Delegation: $resource_based_delegation" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            if [ -s "$vulnerable_file" ]; then
                cat "$vulnerable_file" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
                echo >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            fi
        fi
        
        # Create a highlighted version
        highlight_file "$output_file"
    else
        print_info "No Kerberos-related settings found"
        rm -f "$output_file" "$vulnerable_file"
    fi
}

# Function to analyze Group Policy Objects
analyze_gpos() {
    print_section "Analyzing Group Policy Objects"
    local output_file="${OUTPUT_DIR}/gpo_analysis.txt"
    local gpo_details_file="${OUTPUT_DIR}/gpo_details.txt"
    local gpo_permissions_file="${OUTPUT_DIR}/gpo_permissions.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" displayName gPCFileSysPath nTSecurityDescriptor -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" displayName gPCFileSysPath nTSecurityDescriptor -o ldif-wrap=no"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    # Check for errors
    if [ -s "${output_file}.err" ]; then
        local error_msg=$(cat "${output_file}.err")
        print_warning "Error retrieving GPO information: $error_msg"
        rm -f "${output_file}.err"
    fi
    
    if [ -s "$output_file" ]; then
        print_success "GPO analysis saved to: $output_file"
        echo "${BOLD}${PURPLE}[+] Group Policy Objects Found:${RESET}"
        
        # Process GPOs
        local current_gpo=""
        local current_path=""
        local current_sd=""
        local gpo_count=0
        local interesting_gpos=()
        
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                if [ -n "$current_gpo" ]; then
                    echo
                    echo "GPO: $current_gpo"
                    echo "Path: $current_path"
                    if [ -n "$current_sd" ]; then
                        echo "Security Descriptor: $current_sd"
                        # Check for interesting permissions
                        if [[ "$current_sd" =~ "GenericAll" ]] || \
                           [[ "$current_sd" =~ "WriteDacl" ]] || \
                           [[ "$current_sd" =~ "WriteOwner" ]] || \
                           [[ "$current_sd" =~ "GenericWrite" ]]; then
                            echo "${BOLD}${RED}[!] Interesting Permissions Found${RESET}"
                            interesting_gpos+=("$current_gpo")
                        fi
                    fi
                    echo "----------------------------------------"
                fi
                current_gpo=""
                current_path=""
                current_sd=""
            elif [[ $line =~ ^displayName: ]]; then
                current_gpo=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                ((gpo_count++))
            elif [[ $line =~ ^gPCFileSysPath: ]]; then
                current_path=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
            elif [[ $line =~ ^nTSecurityDescriptor: ]]; then
                current_sd=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
            fi
        done < "$output_file"
        
        # Print the last GPO
        if [ -n "$current_gpo" ]; then
            echo
            echo "GPO: $current_gpo"
            echo "Path: $current_path"
            if [ -n "$current_sd" ]; then
                echo "Security Descriptor: $current_sd"
                # Check for interesting permissions
                if [[ "$current_sd" =~ "GenericAll" ]] || \
                   [[ "$current_sd" =~ "WriteDacl" ]] || \
                   [[ "$current_sd" =~ "WriteOwner" ]] || \
                   [[ "$current_sd" =~ "GenericWrite" ]]; then
                    echo "${BOLD}${RED}[!] Interesting Permissions Found${RESET}"
                    interesting_gpos+=("$current_gpo")
                fi
            fi
        fi
        
        # Get detailed GPO information
        if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
            ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" * -o ldif-wrap=no"
        else
            ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" * -o ldif-wrap=no"
        fi
        
        eval "$ldap_cmd" > "$gpo_details_file" 2>"${gpo_details_file}.err"
        
        # Check for errors
        if [ -s "${gpo_details_file}.err" ]; then
            local error_msg=$(cat "${gpo_details_file}.err")
            print_warning "Error retrieving detailed GPO information: $error_msg"
            rm -f "${gpo_details_file}.err"
        fi
        
        # Analyze GPO permissions
        if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
            ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" nTSecurityDescriptor -o ldif-wrap=no"
        else
            ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=groupPolicyContainer)\" nTSecurityDescriptor -o ldif-wrap=no"
        fi
        
        eval "$ldap_cmd" > "$gpo_permissions_file" 2>"${gpo_permissions_file}.err"
        
        # Check for errors
        if [ -s "${gpo_permissions_file}.err" ]; then
            local error_msg=$(cat "${gpo_permissions_file}.err")
            print_warning "Error retrieving GPO permissions: $error_msg"
            rm -f "${gpo_permissions_file}.err"
        fi
        
        # Print summary
        echo
        echo "${BOLD}${YELLOW}[+] GPO Analysis Summary:${RESET}"
        echo "Total GPOs Found: $gpo_count"
        if [ ${#interesting_gpos[@]} -gt 0 ]; then
            echo "GPOs with Interesting Permissions: ${#interesting_gpos[@]}"
            echo "${BOLD}${RED}[!] GPOs with Interesting Permissions:${RESET}"
            printf "  %s\n" "${interesting_gpos[@]}"
        fi
        
        # Add to buzzworthy findings if interesting GPOs found
        if [ $gpo_count -gt 0 ]; then
            echo "${BOLD}${GREEN}[!] GROUP POLICY OBJECTS${RESET}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Generated on: $(date)" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "===============================================================" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Total GPOs Found: $gpo_count" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            if [ ${#interesting_gpos[@]} -gt 0 ]; then
                echo "GPOs with Interesting Permissions: ${#interesting_gpos[@]}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
                echo "----------------------------------------" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
                printf "  %s\n" "${interesting_gpos[@]}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            fi
            echo >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
        fi
        
        # Create highlighted versions
        highlight_file "$output_file"
        highlight_file "$gpo_details_file"
        highlight_file "$gpo_permissions_file"
    else
        print_info "No Group Policy Objects found"
        rm -f "$output_file" "$gpo_details_file" "$gpo_permissions_file"
    fi
}

# Function to analyze trust relationships
analyze_trusts() {
    print_section "Analyzing Trust Relationships"
    local output_file="${OUTPUT_DIR}/trust_analysis.txt"
    local trust_details_file="${OUTPUT_DIR}/trust_details.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=trustedDomain)\" * -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=trustedDomain)\" * -o ldif-wrap=no"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file" 2>"${output_file}.err"
    
    # Check for errors
    if [ -s "${output_file}.err" ]; then
        local error_msg=$(cat "${output_file}.err")
        print_warning "Error retrieving trust information: $error_msg"
        rm -f "${output_file}.err"
    fi
    
    if [ -s "$output_file" ]; then
        print_success "Trust analysis saved to: $output_file"
        echo "${BOLD}${PURPLE}[+] Trust Relationships Found:${RESET}"
        
        # Process trusts
        local current_trust=""
        local current_type=""
        local current_direction=""
        local current_attributes=()
        local trust_count=0
        local external_trusts=0
        local forest_trusts=0
        local realm_trusts=0
        
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                if [ -n "$current_trust" ]; then
                    echo
                    echo "Trust: $current_trust"
                    echo "Type: $current_type"
                    echo "Direction: $current_direction"
                    if [ ${#current_attributes[@]} -gt 0 ]; then
                        echo "Additional Attributes:"
                        printf "  %s\n" "${current_attributes[@]}"
                    fi
                    echo "----------------------------------------"
                fi
                current_trust=""
                current_type=""
                current_direction=""
                current_attributes=()
            elif [[ $line =~ ^cn: ]]; then
                current_trust=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                ((trust_count++))
            elif [[ $line =~ ^trustType: ]]; then
                current_type=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                case $current_type in
                    *"External"*) ((external_trusts++)) ;;
                    *"Forest"*) ((forest_trusts++)) ;;
                    *"Realm"*) ((realm_trusts++)) ;;
                esac
            elif [[ $line =~ ^trustDirection: ]]; then
                local direction=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                case $direction in
                    0) current_direction="Disabled" ;;
                    1) current_direction="Inbound" ;;
                    2) current_direction="Outbound" ;;
                    3) current_direction="Bidirectional" ;;
                    *) current_direction="Unknown" ;;
                esac
            elif [[ $line =~ ^[a-zA-Z0-9-]*: ]]; then
                # Skip already processed attributes
                if ! [[ $line =~ ^(cn|trustType|trustDirection): ]]; then
                    current_attributes+=("$line")
                fi
            fi
        done < "$output_file"
        
        # Print the last trust
        if [ -n "$current_trust" ]; then
            echo
            echo "Trust: $current_trust"
            echo "Type: $current_type"
            echo "Direction: $current_direction"
            if [ ${#current_attributes[@]} -gt 0 ]; then
                echo "Additional Attributes:"
                printf "  %s\n" "${current_attributes[@]}"
            fi
        fi
        
        # Get detailed trust information
        if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
            ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=trustedDomain)\" * -o ldif-wrap=no"
        else
            ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=trustedDomain)\" * -o ldif-wrap=no"
        fi
        
        eval "$ldap_cmd" > "$trust_details_file" 2>"${trust_details_file}.err"
        
        # Check for errors
        if [ -s "${trust_details_file}.err" ]; then
            local error_msg=$(cat "${trust_details_file}.err")
            print_warning "Error retrieving detailed trust information: $error_msg"
            rm -f "${trust_details_file}.err"
        fi
        
        # Print summary
        echo
        echo "${BOLD}${YELLOW}[+] Trust Analysis Summary:${RESET}"
        echo "Total Trusts Found: $trust_count"
        echo "External Trusts: $external_trusts"
        echo "Forest Trusts: $forest_trusts"
        echo "Realm Trusts: $realm_trusts"
        
        # Add to buzzworthy findings if trusts found
        if [ $trust_count -gt 0 ]; then
            echo "${BOLD}${BLUE}[!] TRUST RELATIONSHIPS${RESET}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Generated on: $(date)" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "===============================================================" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Total Trusts Found: $trust_count" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "External Trusts: $external_trusts" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Forest Trusts: $forest_trusts" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Realm Trusts: $realm_trusts" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "----------------------------------------" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            grep "cn:" "$output_file" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
        fi
        
        # Create highlighted versions
        highlight_file "$output_file"
        highlight_file "$trust_details_file"
    else
        print_info "No trust relationships found"
        rm -f "$output_file" "$trust_details_file"
    fi
}

# Function to analyze service accounts
analyze_service_accounts() {
    print_section "Analyzing Service Accounts"
    local output_file="${OUTPUT_DIR}/service_accounts_analysis.txt"
    local spn_file="${OUTPUT_DIR}/service_principal_names.txt"
    local delegation_file="${OUTPUT_DIR}/service_delegation.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(&(objectClass=user)(servicePrincipalName=*))\" sAMAccountName servicePrincipalName userAccountControl msDS-AllowedToDelegateTo msDS-AllowedToActOnBehalfOfOtherIdentity -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(&(objectClass=user)(servicePrincipalName=*))\" sAMAccountName servicePrincipalName userAccountControl msDS-AllowedToDelegateTo msDS-AllowedToActOnBehalfOfOtherIdentity -o ldif-wrap=no"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file"
    
    if [ -s "$output_file" ]; then
        print_success "Service account analysis saved to: $output_file"
        echo "${BOLD}${PURPLE}[+] Service Accounts Found:${RESET}"
        
        # Process service accounts
        local current_account=""
        local current_spns=()
        local current_delegation=""
        local service_count=0
        local kerberoastable=0
        local constrained=0
        local unconstrained=0
        
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                if [ -n "$current_account" ]; then
                    echo
                    echo "Account: $current_account"
                    if [ ${#current_spns[@]} -gt 0 ]; then
                        echo "SPNs:"
                        printf "  %s\n" "${current_spns[@]}"
                    fi
                    if [ -n "$current_delegation" ]; then
                        echo "Delegation: $current_delegation"
                    fi
                    echo "----------------------------------------"
                fi
                current_account=""
                current_spns=()
                current_delegation=""
            elif [[ $line =~ ^sAMAccountName: ]]; then
                current_account=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                ((service_count++))
            elif [[ $line =~ ^servicePrincipalName: ]]; then
                current_spns+=("$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')")
                ((kerberoastable++))
            elif [[ $line =~ ^msDS-AllowedToDelegateTo: ]]; then
                current_delegation="Constrained Delegation"
                ((constrained++))
            elif [[ $line =~ ^msDS-AllowedToActOnBehalfOfOtherIdentity: ]]; then
                current_delegation="Resource-Based Delegation"
                ((unconstrained++))
            fi
        done < "$output_file"
        
        # Print the last account
        if [ -n "$current_account" ]; then
            echo
            echo "Account: $current_account"
            if [ ${#current_spns[@]} -gt 0 ]; then
                echo "SPNs:"
                printf "  %s\n" "${current_spns[@]}"
            fi
            if [ -n "$current_delegation" ]; then
                echo "Delegation: $current_delegation"
            fi
        fi
        
        # Print summary
        echo
        echo "${BOLD}${YELLOW}[+] Service Account Analysis Summary:${RESET}"
        echo "Total Service Accounts: $service_count"
        echo "Kerberoastable Accounts: $kerberoastable"
        echo "Constrained Delegation: $constrained"
        echo "Unconstrained Delegation: $unconstrained"
        
        # Add to buzzworthy findings if service accounts found
        if [ $service_count -gt 0 ]; then
            echo "${BOLD}${MAGENTA}[!] SERVICE ACCOUNTS${RESET}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Generated on: $(date)" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "===============================================================" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Total Service Accounts: $service_count" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Kerberoastable Accounts: $kerberoastable" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Constrained Delegation: $constrained" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Unconstrained Delegation: $unconstrained" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
        fi
        
        # Create highlighted versions
        highlight_file "$output_file"
    else
        print_info "No service accounts found"
        rm -f "$output_file" "$spn_file" "$delegation_file"
    fi
}

# Function to analyze security descriptors
analyze_security_descriptors() {
    print_section "Analyzing Security Descriptors"
    local output_file="${OUTPUT_DIR}/security_descriptors.txt"
    local interesting_file="${OUTPUT_DIR}/interesting_permissions.txt"
    
    # Build the command
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        ldap_cmd="ldapsearch -x -H ldap://${IP} -D \"${USERNAME}@${DOMAIN}\" -w \"${PASSWORD}\" -b \"${BASE_DN}\" \"(objectClass=*)\" nTSecurityDescriptor -o ldif-wrap=no"
    else
        ldap_cmd="ldapsearch -x -H ldap://${IP} -b \"${BASE_DN}\" \"(objectClass=*)\" nTSecurityDescriptor -o ldif-wrap=no"
    fi
    
    # Execute the command
    eval "$ldap_cmd" > "$output_file"
    
    if [ -s "$output_file" ]; then
        print_success "Security descriptor analysis saved to: $output_file"
        echo "${BOLD}${PURPLE}[+] Security Descriptors Found:${RESET}"
        
        # Process security descriptors
        local current_object=""
        local current_sd=""
        local interesting_count=0
        
        while read -r line; do
            if [[ $line =~ ^dn: ]]; then
                if [ -n "$current_object" ]; then
                    echo
                    echo "Object: $current_object"
                    if [ -n "$current_sd" ]; then
                        echo "Security Descriptor: $current_sd"
                        # Check for interesting permissions
                        if [[ "$current_sd" =~ "GenericAll" ]] || \
                           [[ "$current_sd" =~ "WriteDacl" ]] || \
                           [[ "$current_sd" =~ "WriteOwner" ]] || \
                           [[ "$current_sd" =~ "GenericWrite" ]]; then
                            echo "${BOLD}${RED}[!] Interesting Permissions Found${RESET}"
                            echo "Object: $current_object" >> "$interesting_file"
                            echo "Security Descriptor: $current_sd" >> "$interesting_file"
                            echo "----------------------------------------" >> "$interesting_file"
                            ((interesting_count++))
                        fi
                    fi
                    echo "----------------------------------------"
                fi
                current_object=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                current_sd=""
            elif [[ $line =~ ^nTSecurityDescriptor: ]]; then
                current_sd=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
            fi
        done < "$output_file"
        
        # Print the last object
        if [ -n "$current_object" ]; then
            echo
            echo "Object: $current_object"
            if [ -n "$current_sd" ]; then
                echo "Security Descriptor: $current_sd"
                # Check for interesting permissions
                if [[ "$current_sd" =~ "GenericAll" ]] || \
                   [[ "$current_sd" =~ "WriteDacl" ]] || \
                   [[ "$current_sd" =~ "WriteOwner" ]] || \
                   [[ "$current_sd" =~ "GenericWrite" ]]; then
                    echo "${BOLD}${RED}[!] Interesting Permissions Found${RESET}"
                    echo "Object: $current_object" >> "$interesting_file"
                    echo "Security Descriptor: $current_sd" >> "$interesting_file"
                    echo "----------------------------------------" >> "$interesting_file"
                    ((interesting_count++))
                fi
            fi
        fi
        
        # Print summary
        echo
        echo "${BOLD}${YELLOW}[+] Security Descriptor Analysis Summary:${RESET}"
        echo "Total Objects with Security Descriptors: $(grep -c "^dn:" "$output_file")"
        echo "Objects with Interesting Permissions: $interesting_count"
        
        # Add to buzzworthy findings if interesting permissions found
        if [ $interesting_count -gt 0 ]; then
            echo "${BOLD}${RED}[!] INTERESTING PERMISSIONS${RESET}" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "Generated on: $(date)" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo "===============================================================" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            cat "$interesting_file" >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
            echo >> "${OUTPUT_DIR}/buzzworthy_findings.txt"
        fi
        
        # Create highlighted versions
        highlight_file "$output_file"
        if [ -s "$interesting_file" ]; then
            highlight_file "$interesting_file"
        fi
    else
        print_info "No security descriptors found"
        rm -f "$output_file" "$interesting_file"
    fi
}

# Start LDAP enumeration
print_section "Starting LDAP Enumeration"

# 1. Initial Connection and Authentication
# Try to find the naming context if needed
find_naming_context

# Test the connection
if ! test_null_bind; then
    if ! test_auth_bind; then
        print_warning "Could not connect to LDAP server. Try providing credentials."
        print_warning "Usage: $0 <IP> <Domain> <Username> <Password>"
        print_info "Example: $0 10.10.10.182 cascade.local 'user@cascade.local' 'password123'"
        print_info "For Active Directory, try using domain\\username format:"
        print_info "$0 10.10.10.182 cascade.local 'CASCADE\\username' 'password'"
        
        # Create the log file
        mkdir -p "$OUTPUT_DIR"
        echo "LDAP enumeration failed - connection issues" > "$LOG_FILE"
        echo "Attempted with:" >> "$LOG_FILE"
        echo "  IP: $IP" >> "$LOG_FILE"
        echo "  Domain: $DOMAIN" >> "$LOG_FILE"
        echo "  Base DN: $BASE_DN" >> "$LOG_FILE"
        if [ -n "$USERNAME" ]; then
            echo "  Username: $USERNAME" >> "$LOG_FILE"
        fi
        
        exit 1
    fi
fi

echo

# 2. Basic Domain Information
print_section "Gathering Basic Domain Information"
# Domain information
run_ldapsearch "(objectClass=domain)" "${OUTPUT_DIR}/domain_info.txt" "Domain Information" "" "domain"
# Domain DNS information
run_ldapsearch "(objectClass=domainDNS)" "${OUTPUT_DIR}/domain_dns.txt" "Domain DNS"
# Domain policy
run_ldapsearch "(objectClass=domainPolicy)" "${OUTPUT_DIR}/domain_policy.txt" "Domain Policy"

# 3. Authentication and Credentials
print_section "Analyzing Authentication and Credentials"
# Test common credentials if no credentials provided
if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    test_common_credentials
fi
# Check password policy details
check_password_policy_details
# Check password policy
check_password_policy

# 4. User and Group Analysis
print_section "Analyzing Users and Groups"
# Users
run_ldapsearch "(objectClass=user)" "${OUTPUT_DIR}/users.txt" "User Accounts" "" "users"
# Computers
run_ldapsearch "(objectClass=computer)" "${OUTPUT_DIR}/computers.txt" "Computer Accounts" "" "computers"
# Groups
run_ldapsearch "(objectClass=group)" "${OUTPUT_DIR}/groups.txt" "Groups" "" "groups"
# Privileged accounts
run_ldapsearch "(&(objectClass=user)(|(memberOf=*admin*)(sAMAccountName=*admin*)))" "${OUTPUT_DIR}/privileged_accounts.txt" "Privileged Accounts" "" "privileged"
# Service accounts
run_ldapsearch "(&(objectClass=user)(|(name=*svc*)(name=*service*)(description=*service*)))" "${OUTPUT_DIR}/service_accounts.txt" "Service Accounts" "" "service"
# Check user attributes
check_user_attributes

# 5. Security Analysis
print_section "Analyzing Security Settings"
# Analyze Kerberos settings
analyze_kerberos
# Check for delegation
check_delegation
# Check interesting ACLs
check_interesting_acls
# Analyze security descriptors
analyze_security_descriptors
# Scan for custom attributes
scan_custom_attributes

# 6. Group Policy and Trust Analysis
print_section "Analyzing Group Policies and Trusts"
# Analyze Group Policy Objects
analyze_gpos
# Check GPOs
check_gpos
# Analyze trust relationships
analyze_trusts
# Trust relationships
run_ldapsearch "(objectClass=trustedDomain)" "${OUTPUT_DIR}/trust_relationships.txt" "Trust Relationships"

# 7. Service and Resource Analysis
print_section "Analyzing Services and Resources"
# Analyze service accounts
analyze_service_accounts
# Check SPNs
check_spns
# Accounts with SPNs (potential kerberoasting)
run_ldapsearch "(&(objectClass=user)(servicePrincipalName=*))" "${OUTPUT_DIR}/spn_accounts.txt" "Accounts with SPNs (Kerberoasting Candidates)"
# Check shares
check_shares

# 8. Description and Attribute Analysis
print_section "Analyzing Descriptions and Attributes"
# Check descriptions
check_descriptions
# Potentially interesting descriptions
run_ldapsearch "(description=*)" "${OUTPUT_DIR}/descriptions.txt" "Objects with Descriptions"
# Additional: Look for potentially interesting attributes in descriptions
run_ldapsearch "(&(objectClass=user)(|(description=*pwd*)(description=*password*)(description=*cred*)))" "${OUTPUT_DIR}/pwd_in_desc.txt" "Accounts with Password Info in Description"
# Search for interesting attributes
search_interesting_attributes

# 9. Account Status Analysis
print_section "Analyzing Account Status"
# Non-expired accounts
run_ldapsearch "(&(objectClass=user)(!(accountExpires=0))(!(accountExpires=9223372036854775807)))" "${OUTPUT_DIR}/non_expired_accounts.txt" "Non-expired Accounts"

# 10. Fallback Search
# Try a broader search if most queries returned no results
if [ ! -f "${OUTPUT_DIR}/users.txt" ] && [ ! -f "${OUTPUT_DIR}/groups.txt" ]; then
    print_warning "Most specific queries returned no results. Trying broader search..."
    run_ldapsearch "(objectClass=*)" "${OUTPUT_DIR}/all_objects.txt" "All LDAP Objects"
fi

# 11. Post-Processing
print_section "Post-Processing Results"
# Process buzzworthy findings
filter_buzzworthy "${OUTPUT_DIR}/interesting_attributes.txt"

# Process only the original files, not the highlighted or summary files
for file in "${OUTPUT_DIR}"/*.txt; do
    if [ -f "$file" ] && [ -s "$file" ] && \
       [[ ! "$file" == *"_highlighted.txt" ]] && \
       [[ ! "$file" == *"_summary.txt" ]]; then
        highlight_file "$file"
    fi
done

# Create a master summary file
print_info "Creating master summary"
{
    echo "${BOLD}LDAP Enumeration Summary for $IP ($DOMAIN)${RESET}"
    echo "Generated on: $(date)"
    echo "==============================================================="
    echo
    
    if [ -f "${OUTPUT_DIR}/domain_info_summary.txt" ]; then
        echo "${BOLD}${GREEN}DOMAIN INFORMATION:${RESET}"
        cat "${OUTPUT_DIR}/domain_info_summary.txt"
        echo
    fi
    
    if [ -f "${OUTPUT_DIR}/privileged_accounts_summary.txt" ]; then
        echo "${BOLD}${RED}PRIVILEGED ACCOUNTS:${RESET}"
        cat "${OUTPUT_DIR}/privileged_accounts_summary.txt"
        echo
    fi
    
    if [ -f "${OUTPUT_DIR}/service_accounts_summary.txt" ]; then
        echo "${BOLD}${YELLOW}SERVICE ACCOUNTS:${RESET}"
        cat "${OUTPUT_DIR}/service_accounts_summary.txt"
        echo
    fi
    
    if [ -f "${OUTPUT_DIR}/spn_accounts_summary.txt" ]; then
        echo "${BOLD}${MAGENTA}KERBEROASTING CANDIDATES:${RESET}"
        cat "${OUTPUT_DIR}/spn_accounts_summary.txt"
        echo
    fi
    
    if [ -f "${OUTPUT_DIR}/trust_relationships_summary.txt" ]; then
        echo "${BOLD}${BLUE}TRUST RELATIONSHIPS:${RESET}"
        cat "${OUTPUT_DIR}/trust_relationships_summary.txt"
        echo
    fi
    
    if [ -f "${OUTPUT_DIR}/pwd_in_desc_summary.txt" ]; then
        echo "${BOLD}${RED}POSSIBLE PASSWORD INFO IN DESCRIPTIONS:${RESET}"
        cat "${OUTPUT_DIR}/pwd_in_desc_summary.txt"
        echo
    fi
    
    echo "${BOLD}FILE LISTING:${RESET}"
    ls -la "${OUTPUT_DIR}" | grep -v "summary\|highlighted\|\.err" | grep "\.txt"
} > "${OUTPUT_DIR}/master_summary.txt"

# Final message
print_section "Enumeration Complete"
print_success "All results saved to: ${OUTPUT_DIR}"
print_success "Master summary: ${OUTPUT_DIR}/master_summary.txt"
echo
echo "${BOLD}${GREEN}Files to review first:${RESET}"
echo "1. ${YELLOW}${OUTPUT_DIR}/master_summary.txt${RESET} - Overview of all findings"
echo "2. ${YELLOW}${OUTPUT_DIR}/pwd_in_desc_highlighted.txt${RESET} - Check for password info"
echo "3. ${YELLOW}${OUTPUT_DIR}/privileged_accounts_highlighted.txt${RESET} - Admin accounts"
echo "4. ${YELLOW}${OUTPUT_DIR}/descriptions_highlighted.txt${RESET} - Check for sensitive info"
echo
print_info "To search across all files: ${CYAN}grep -i \"password\" ${OUTPUT_DIR}/*.txt${RESET}"
echo
echo "${BOLD}${GREEN}Troubleshooting:${RESET}"
echo "- If you're getting no results, try running with credentials:"
echo "  ${CYAN}$0 $IP $DOMAIN 'username@$DOMAIN' 'password'${RESET}"
echo "- For Active Directory, try using domain\\username format:"
echo "  ${CYAN}$0 $IP $DOMAIN 'CASCADE\\username' 'password'${RESET}"
echo "- Or try null authentication with a specific username:"
echo "  ${CYAN}ldapsearch -x -H ldap://$IP -D 'username@$DOMAIN' -w '' -b '$BASE_DN' '(objectClass=*)'${RESET}"
echo