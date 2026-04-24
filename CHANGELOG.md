# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- _Nothing yet_

### Changed
- _Nothing yet_

### Fixed
- _Nothing yet_

---

## [0.1.0] - 2025-01-01

### Added
- `vulnerable/missing_auth`: Token contract with missing `require_auth` on transfer, demonstrating improper authorization checks
- `vulnerable/unchecked_math`: Staking contract using raw arithmetic, vulnerable to overflow/underflow
- `vulnerable/unprotected_admin`: Contract with admin functions lacking proper access control
- `vulnerable/unsafe_storage`: Contract demonstrating insecure storage patterns
- `secure/secure_vault`: Secure vault implementation with proper authorization and safe design
- `secure/protected_admin`: Contract with correctly implemented admin access control
- `registry`: Contract registry system for managing deployed contracts
