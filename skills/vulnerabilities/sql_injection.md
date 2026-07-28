---
name: sql-injection
description: SQL injection testing covering union, blind, error-based, and ORM bypass techniques
---
# SQL Injection

## Attack Surface
Any input field, URL parameter, or header that reaches a database query.

## Key Vulnerabilities
Union-based, blind (boolean/time), error-based, and second-order injection.

## Testing Methodology
Fuzz inputs with quote characters and boolean payloads, watch for error messages or timing differences.
