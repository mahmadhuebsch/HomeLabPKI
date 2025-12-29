# Security Policy

## Important Security Notice

HomeLab PKI is designed for **development, testing, and internal infrastructure** purposes. It is **not recommended** for production PKI infrastructure without additional security hardening.

## Security Considerations

### Private Key Storage

- **Private keys are stored unencrypted** on disk. It is highly recommended to choose a strong password.
- Ensure proper file system permissions (e.g., `chmod 600` for key files on Unix systems)
- Consider encrypting the `ca-data` directory at the file system level

### Access Control

- This application has built-in authentication. Passwords are stored encrypted
- For any network-accessible deployment, place behind a reverse proxy
- Limit network access to trusted users only

### HTTPS

- The application runs over HTTP by default
- Always use HTTPS when deploying in any networked environment. Otherwise, the passwords are transferred unencrypted.
- Consider using a reverse proxy (nginx, Apache, Caddy) for TLS termination

### Certificate Security

- Root CA private keys should be kept offline when possible
- Use Intermediate CAs for day-to-day certificate signing
- Regularly rotate certificates before expiration
- Monitor certificate expiration dates

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email the maintainers directly with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

I will acknowledge receipt within 48 hours and provide an estimated timeline for a fix.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Security Best Practices

When using HomeLab PKI:

1. **Network Security**
   - Run on localhost only, or behind a firewall
   - Use VPN for remote access
   - Implement network segmentation

2. **Backup Security**
   - Regularly backup the `ca-data` directory
   - Encrypt backups containing private keys
   - Store backups securely offline

3. **Operational Security**
   - Review application logs regularly
   - Monitor for unauthorized access attempts
   - Keep dependencies updated

4. **Key Management**
   - Use strong key sizes (4096-bit RSA for CAs, 2048-bit for server certs)
   - Protect private key exports
   - Consider hardware security modules (HSM) for production environments

## Dependency Security

We regularly update dependencies to address known vulnerabilities. To check for vulnerable dependencies:

```bash
pip install safety
safety check -r requirements.txt
```

## Disclaimer

This software is provided "as is" without warranty of any kind. Users are responsible for:
- Proper security configuration
- Access control implementation
- Compliance with their organization's security policies
- Understanding the risks of PKI infrastructure management
