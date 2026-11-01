# Security

Security fixes target the latest published release. Before 1.0 the minor
version is the breaking one; a fix ships as a patch of the current minor.

Report suspected vulnerabilities privately using **Report a vulnerability** on
[GitHub Security](https://github.com/hupe1980/iso15118/security). If that action
is unavailable, do not post vulnerability details publicly.

Include the affected version and feature flags, a minimal reproducer (the bytes,
their `PayloadType` and the negotiated protocol, and which side sends them) and
the potential impact. Use test certificates; never include a real contract
certificate, private key or EMAID.

In scope: everything this crate decodes, sequences or verifies. The caller's:
transport and TLS, certificate revocation, randomness (session ids,
`GenChallenge`, SLAC keys) and connection limits. Reports about those are
welcome; they may become documentation rather than a fix.

Each release carries a CycloneDX SBOM and a build-provenance attestation for the
published `.crate` (`gh attestation verify`).
