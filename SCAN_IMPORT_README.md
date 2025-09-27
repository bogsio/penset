# Scan Results Import Guide

This guide explains how to import scan results from ZIP files into the Penset database.

## Quick Start

1. **Prepare your ZIP file** with scan results in the expected structure
2. **Use the management command** to import the results
3. **View results** in the Django admin interface

## Management Command

```bash
uv run python manage.py import_scan_results <zip_file> --name "Scan Name" --description "Description"
```

### Example

```bash
uv run python manage.py import_scan_results test_scan_results.zip --name "KeepSimple Recon" --description "Reconnaissance scan of keepsimple.dev"
```

## Expected ZIP Structure

Your ZIP file should contain the following structure:

```
scan_results.zip
├── enriched_summary_report.json          # Reconnaissance summary
├── vulnerability_summary_report.json     # Vulnerability summary  
├── exploitation_summary_report.json      # Exploitation summary
├── domains/
│   └── all_domains.txt                   # Discovered domains
├── ips/
│   └── all_ips.txt                       # Discovered IP addresses
├── ports/
│   └── open_ports.json                   # Port scanning results
├── services/
│   └── detected_services.json            # Service detection results
├── web/
│   └── web_enumeration.json              # Web enumeration results
├── vulnerabilities/
│   ├── nuclei_results.json               # Nuclei scan results
│   ├── nikto_results.json                # Nikto scan results
│   ├── sqlmap_results.json               # SQLMap scan results
│   └── ssl_scan_results.json             # SSL scan results
├── exploits/
│   └── exploit_*.py                      # Generated exploit scripts
└── exploit_results/
    ├── successful_exploits.json          # Successful exploitation results
    ├── failed_exploits.json              # Failed exploitation results
    └── exploit_attempts.json             # All exploitation attempts
```

## What Gets Created

The import process creates:

- **ScanSession**: Main container with metadata and status
- **Targets**: All discovered domains, IPs, URLs with relationships
- **ScanResults**: Categorized results (reconnaissance, vulnerability, exploitation)
- **ScanArtifacts**: Generated exploit scripts and reports

## Admin Interface

After importing, you can view and manage the results through the Django admin interface:

1. Go to `/admin/reports/scansession/` to see all scan sessions
2. Click on a scan session to view details
3. Use the "Show import instructions" action for help

## Test Data

A test ZIP file (`test_scan_results.zip`) is available for testing the import functionality.

## Troubleshooting

### Common Issues

1. **ZIP file not found**: Make sure the file path is correct
2. **Invalid ZIP**: Ensure the file is a valid ZIP archive
3. **Missing files**: Check that the ZIP contains the expected structure
4. **User not found**: Make sure the specified user exists

### Error Messages

- `ZIP file does not exist`: Check the file path
- `User does not exist`: Use a valid username (default: 'admin')
- `Error processing archive`: Check the ZIP file structure and content

## API Access

After importing, you can access the data via the REST API:

- `GET /api/reports/scans/` - List all scan sessions
- `GET /api/reports/scans/{id}/` - Get scan session details
- `GET /api/reports/scans/{id}/targets/` - Get scan targets
- `GET /api/reports/scans/{id}/results/` - Get scan results
- `GET /api/reports/scans/{id}/artifacts/` - Get scan artifacts

## Support

For issues or questions, check the Django logs or contact the development team.
