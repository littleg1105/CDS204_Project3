# E-Shop Vulnerable Version

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes only!**

## Quick Links

- **Full Documentation**: See [MASTER_VULNERABILITY_DOCUMENTATION.md](MASTER_VULNERABILITY_DOCUMENTATION.md)
- **Individual Vulnerabilities**: See [Documentation/VULNERABILITIES/](Documentation/VULNERABILITIES/)
- **Penetration Test Reports**: See [Documentation/REPORT_ATTEMPTS/](Documentation/REPORT_ATTEMPTS/)

## Quick Start

```bash
cd secure_eshop
source venv/bin/activate  # or venv\Scripts\activate on Windows
python manage.py runserver

# Default credentials
Username: admin
Password: admin123
```

## Vulnerability Summary

| Vulnerability | Endpoint | Severity |
|--------------|----------|----------|
| SQL Injection | `/catalog/?q=` | CRITICAL |
| Stored XSS | Product reviews | HIGH |
| IDOR | `/order/<id>/` | HIGH |
| CSRF | `/transfer-credits/` | HIGH |
| User Enumeration | `/login/` | MEDIUM |

## Important Notes

- Orders use format `ORD-XXXXX-XXXXX` (not sequential integers)
- Navigation is in Greek (Κατάλογος, Καλάθι, Προφίλ, etc.)
- Custom user model `eshop.CustomUser` is used
- All vulnerabilities are marked with comments in the code

**For detailed exploitation guides and technical documentation, see the master documentation file.**