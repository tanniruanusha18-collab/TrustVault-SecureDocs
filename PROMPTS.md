# TrustVault — AI Usage and Verification Log

This document records how AI assistance was used during TrustVault development, what was checked, and what was learned. Entries describe the work completed so far; future work should be added as it happens.

## Entry 1 — 2026-10-21: Project Setup and Git

**Prompt / task:** Guide me step by step through setting up the TrustVault project, using Git, and publishing the repository to GitHub.

**AI assistance:** Received beginner-friendly instructions for terminal commands and GitHub operations.

**Verification:** Checked the terminal output after commits and pushes to confirm that Git accepted the changes.

**Learning:** A successful push confirms that changes reached the remote repository; it does not prove that the application is secure or correct.

## Entry 2 — 2026-10-21: Basic Automated Tests

**Prompt / task:** Help create automated tests for registration, login, and document security.

**AI assistance:** Worked on pytest tests using Flask's test client.

**Verification:** Ran `python -m pytest -v` and inspected the individual test results.

**Learning:** Automated tests provide repeatable evidence for specific behaviors, but a passing test suite does not cover every possible security attack.

## Entry 3 — 2026-10-21: Document Authorization

**Prompt / task:** Help inspect the document download route and understand how document permissions are checked.

**AI assistance:** Reviewed the authorization logic and the difference between read and edit permissions.

**Verification:** Added a test that confirms another user cannot download a private document and expects HTTP 403.

**Learning:** Hiding a download link in the interface is not enough. Authorization must be checked on the server for every protected request.

## Entry 4 — 2026-10-22: Permission Revocation

**Prompt / task:** Help test whether a user loses access immediately after a document owner revokes permission.

**AI assistance:** Created a test flow that grants read access, confirms a successful download, revokes access, and then checks the download again.

**Verification:** Ran `python -m pytest -v`; the revocation test passed along with the other tests in the suite.

**Learning:** Permission revocation must affect subsequent server-side access checks. A previous successful download must not imply continued access.

## Entry 5 — 2026-10-22: Test File Recovery and Verification

**Prompt / task:** Help update the test suite and diagnose issues while editing the test file.

**AI assistance:** Provided test code and step-by-step instructions for saving and running it.

**Issue encountered:** During editing, existing test content was replaced rather than simply adding the intended test. The test file had to be restored with the complete test suite.

**Correction and verification:** Replaced the file with the full set of five tests and ran `python -m pytest -v`. All five tests passed.

**Learning:** AI-generated changes must be reviewed against the existing project. Before replacing a file, inspect its current contents and preserve working tests.

## AI Use and Limitations

AI was used as a development assistant for explanations, test-writing guidance, troubleshooting, and documentation. Commands, test results, and repository operations were checked in the local development environment.

AI assistance does not replace security review. The project still requires verification of role-based access control, permission-change authorization, audit integrity, CSRF protection, upload validation, and deployment security before production use.

## Further Work

For each significant future AI-assisted change, add the date, the actual prompt or a faithful summary, the proposed output, any incorrect or incomplete advice discovered, the correction made, and the relevant Git commit. Do not record unverified claims as completed work.