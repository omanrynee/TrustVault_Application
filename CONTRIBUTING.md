# Contributing to TrustVault

Thank you for improving TrustVault.

## Development Setup

1. Create and activate a Python virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the test suite:

```bash
pytest -q
```

## Security Rules

- Do not add unencrypted private-key output.
- New certificates must be signed by the TrustVault Root CA.
- Cryptographic operations must validate certificate trust, expiry, and revocation.
- Add audit logging for security-sensitive behavior.
- Add tests for new PKI, authentication, replay, or encryption behavior.

## Pull Request Checklist

- Tests pass locally.
- No hardcoded credentials are introduced.
- CLI and GUI entry points remain compatible.
- README is updated when behavior changes.
