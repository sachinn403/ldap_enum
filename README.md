# LDAP Enumeration Tool

A comprehensive LDAP enumeration script for penetration testing and security assessments. This tool performs detailed LDAP enumeration using `ldapsearch` and provides organized output of findings.

## Features

- **Comprehensive LDAP Enumeration**
  - Domain information gathering
  - User and group enumeration
  - Computer account discovery
  - Service account identification
  - Group Policy Object analysis
  - Trust relationship analysis
  - Security descriptor analysis
  - Custom attribute scanning

- **Security Analysis**
  - Password policy analysis
  - Kerberos settings analysis
  - Delegation checks
  - ACL analysis
  - SPN enumeration
  - Share enumeration
  - Description analysis

- **Advanced Features**
  - Common credential testing
  - Custom attribute detection
  - Sensitive information scanning
  - Buzzworthy findings identification
  - Color-coded output
  - Organized file structure
  - Detailed summaries

## Requirements

- `ldapsearch` (from ldap-utils package)
- Bash shell
- Basic Unix tools (grep, awk, sed, cut, sort, uniq)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ldap_enum.git
```

2. Make the script executable:
```bash
chmod +x ldap_enum.sh
```

3. Install required dependencies:
```bash
# For Debian/Ubuntu
sudo apt-get install ldap-utils

# For RHEL/CentOS
sudo yum install openldap-clients
```

## Usage

Basic usage:
```bash
./ldap_enum.sh <IP> <Domain> [Username] [Password]
```

Examples:
```bash
# Anonymous enumeration
./ldap_enum.sh 10.10.10.182 example.com

# With credentials (username@domain format)
./ldap_enum.sh 10.10.10.182 example.com 'user@example.com' 'password123'

# With credentials (DOMAIN\username format)
./ldap_enum.sh 10.10.10.182 example.com 'EXAMPLE\username' 'password'
```

## Output Structure

The script creates an output directory named `ldap_enum_<IP>` containing:

- **Basic Information**
  - `domain_info.txt` - Domain details
  - `domain_dns.txt` - DNS information
  - `domain_policy.txt` - Domain policy

- **User and Group Information**
  - `users.txt` - All user accounts
  - `computers.txt` - Computer accounts
  - `groups.txt` - Group information
  - `privileged_accounts.txt` - Privileged accounts
  - `service_accounts.txt` - Service accounts

- **Security Analysis**
  - `kerberos_analysis.txt` - Kerberos settings
  - `delegation.txt` - Delegation information
  - `interesting_acls.txt` - Interesting ACLs
  - `security_descriptors.txt` - Security descriptors
  - `custom_attributes.txt` - Custom attributes

- **Group Policy and Trusts**
  - `gpo_analysis.txt` - Group Policy Objects
  - `trust_analysis.txt` - Trust relationships

- **Service and Resource Information**
  - `spns_detailed.txt` - Service Principal Names
  - `shares.txt` - Network shares

- **Description Analysis**
  - `descriptions.txt` - Object descriptions
  - `pwd_in_desc.txt` - Password information in descriptions

- **Summaries**
  - `master_summary.txt` - Overview of all findings
  - `buzzworthy_findings.txt` - Important security findings

## Troubleshooting

1. **Connection Issues**
   - Verify LDAP server accessibility
   - Check port 389 (or 636 for LDAPS)
   - Ensure correct IP and domain

2. **Authentication Problems**
   - Try different username formats:
     - `username@example.com`
     - `EXAMPLE\username`
     - Just `username`
   - Verify credentials
   - Check for account lockout

3. **No Results**
   - Try with credentials
   - Check permissions
   - Verify base DN
   - Try broader search

## Security Considerations

- This tool is for authorized security testing only
- Do not use against systems without permission
- Be careful with credentials in command history
- Consider using LDAPS for secure connections
- Clean up output files after use

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by various LDAP enumeration tools
- Built on standard LDAP utilities
- Community contributions and feedback

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any system. 