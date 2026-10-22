# TrustVault Security Threat Model

**Project:** TrustVault – Secure Document Sharing with Accountability  
**Last updated:** October 22, 2026

## 1. Assets to Protect

- Uploaded documents and their contents.
- User accounts and password hashes.
- Document ownership and access permissions.
- Audit events and activity records.
- Stored files and application configuration.

## 2. Threats and Mitigations

| Threat | Potential Impact | Mitigation | Verification |
|---|---|---|---|
| Unauthorized document download | Private information is exposed | Check authentication and document-level read permission on every download request | Test that another user receives HTTP 403 |
| Access after permission revocation | A user retains access after the owner revokes it | Check current permissions on every request instead of relying on an old permission decision | Test that download succeeds before revocation and fails afterward |
| Malicious file upload | Unsafe or unexpected files enter storage | Allow only approved file extensions and validate uploaded files | Test rejection of a `.exe` upload |
| Password theft or disclosure | An attacker takes over an account | Store password hashes instead of plaintext passwords | Review registration and login code |
| Unauthorized permission changes | An attacker shares or revokes someone else's document | Require the document owner or an authorized administrator to perform permission changes | Test unauthorized permission-change attempts |
| Audit information exposure | Users see activity records they should not access | Restrict audit views to authorized users and relevant records | Test access restrictions on the audit route |
| Audit record tampering | Suspicious activity is hidden or altered | Restrict access to audit records and consider append-only external logging or hash chaining | Review audit-record write and access paths |
| Cross-site request forgery (CSRF) | A logged-in user is tricked into submitting an unwanted action | Add CSRF protection to state-changing forms and requests | Add tests for requests without valid CSRF tokens |
| Database or file-storage exposure | Private files or metadata are accessed directly | Keep private files outside the public static directory and serve them only through authorized routes | Inspect storage configuration and test protected downloads |

## 3. Trust Boundaries

- **Browser to application:** Treat all form fields, filenames, and requests as untrusted.
- **Application to database:** Validate inputs and enforce ownership and permission rules.
- **Application to file storage:** Do not expose stored files through public URLs.
- **Application to audit records:** Record security-sensitive events and restrict access to their contents.

## 4. Security Assumptions

- Users may attempt to access documents belonging to other users.
- A user may try to reuse access after it has been revoked.
- Uploaded files and submitted form values may be malicious.
- The application server and its storage environment are configured and maintained by a trusted operator.

## 5. Known Limitations and Accepted Risks

This project is a development version and is not yet ready for production deployment.

- File validation may rely partly on filename extensions; extensions alone do not prove that file contents are safe.
- Audit records are not currently guaranteed to be tamper-evident.
- CSRF protection must be implemented and tested before production use.
- A complete administrator role and its authorization rules still need to be verified.
- Production deployment requires secure configuration, HTTPS, protected secrets, backups, and a production-grade application server.
- The current test suite covers basic registration, login, upload rejection, unauthorized download, and permission revocation. Additional tests are needed for the remaining threats.

## 6. Security Testing Plan

1. Verify that users cannot download documents without permission.
2. Verify that revoked access stops working immediately.
3. Verify that unauthorized users cannot grant or revoke permissions.
4. Verify that invalid or disallowed uploads are rejected.
5. Verify that audit records are created for security-sensitive actions and denied attempts.
6. Verify that users cannot view unauthorized audit information.
7. Add CSRF tests and tests for malformed or unexpected inputs.

## 7. Future Improvements

- Implement and test role-based access control for administrators, owners, and viewers.
- Add CSRF protection to all state-changing operations.
- Improve file-content validation and upload size limits.
- Make audit records tamper-evident and restrict database access.
- Add automated tests for permission changes, audit events, and administrator actions.
- Deploy only after security checks and production configuration are complete.