# Cert Recon

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> **TLS certificate intelligence gatherer — SAN extraction, expiry flags, passive crt.sh discovery.**

## Usage

```bash
# Scan hosts for TLS cert info
python cert_recon.py scan example.com api.example.com:8443

# Passive discovery via crt.sh
python cert_recon.py passive example.com --out certs.json
```

## Disclaimer

> **Authorized security testing only.**

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)
