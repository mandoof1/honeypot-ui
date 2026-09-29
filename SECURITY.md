# Security Policy

## Supported Versions

HoneySentinel is a capstone platform. The supported version is the latest
commit on the default branch.

| Version          | Supported          |
| ---------------- | ------------------ |
| `master` (latest) | :white_check_mark: |

## Scope

This project handles two things that need care:

* **Secrets and keys** – signing, encryption, and ingest tokens. Never commit
  these. `.env` files are intentionally ignored.
* **Captured honeypot data** – transcripts, credentials, and session evidence
  are sensitive. They are encrypted/convolved at rest where implemented, and
  must never be committed to the repository. Use synthetic fixtures in tests
  and screenshots.

## Reporting a Vulnerability

Do **not** open a public issue for a security problem. Instead:

* Email the maintainers privately, or
* Use the **Security → Report a vulnerability / Private vulnerability
  reporting** tab on this repository.

Include:

* A description of the issue and the affected file(s).
* Steps to reproduce.
* Impact, and a proposed fix if you have one.

You should receive an acknowledgment within 48 hours and a fix plan shortly
after. Please do not disclose the issue publicly until it is resolved.