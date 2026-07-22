"""
MANUAL DYNAMIC TESTING - Phase 2, stand-in for a formal DAST tool
-----------------------------------------------------------------------
Real DAST tools (OWASP ZAP, Burp Suite) attack a RUNNING web application
over the network. This script is a local command-line tool, not a web
app, so a real DAST scanner can't point at it directly.

Instead, this script does the same THING a DAST tool does conceptually:
feed the running program a set of unexpected / malicious / edge-case
inputs while it's actually executing, and record how it behaves -
rather than just reading the source code (which would be static
analysis instead).

Each test case is intentionally "hostile" input a real attacker or a
careless user might submit, to see if validate_input() in
secure_version.py correctly rejects it.
"""

from secure_version import validate_input

# Each test case: (description, username, password, email, expect_accept)
test_cases = [
    ("Empty username", "", "GoodPass123", "test@example.com", False),
    ("Empty password", "testuser", "", "test@example.com", False),
    ("Empty email", "testuser", "GoodPass123", "", False),
    ("Very short password", "testuser", "abc", "test@example.com", False),
    ("Extremely long input (10,000 chars)", "testuser", "a" * 10000, "test@example.com", True),
    ("Malformed email - no @ symbol", "testuser", "GoodPass123", "test.example.com", False),
    ("Malformed email - no dot", "testuser", "GoodPass123", "test@examplecom", False),
    ("SQL-injection-style string", "testuser", "' OR '1'='1", "test@example.com", True),
    ("Script-injection-style string", "<script>alert(1)</script>", "GoodPass123", "test@example.com", True),
    ("Unicode / emoji input", "tester😀", "GoodPass123", "test@example.com", True),
    ("Whitespace-only password", "testuser", "        ", "test@example.com", True),
    ("Valid, well-formed input", "gooduser", "StrongPass123!", "good@example.com", True),
]

print("=" * 70)
print("MANUAL DYNAMIC TESTING - feeding hostile/edge-case input at runtime")
print("=" * 70)

pass_count = 0
fail_count = 0

for description, username, password, email, expect_accept in test_cases:
    accepted, message = validate_input(username, password, email)
    behaved_as_expected = (accepted == expect_accept)

    status = "OK" if behaved_as_expected else "UNEXPECTED"
    result_word = "ACCEPTED" if accepted else "REJECTED"

    print(f"[{status}] {description}")
    print(f"         -> {result_word}" + (f" ({message})" if message else ""))

    if behaved_as_expected:
        pass_count += 1
    else:
        fail_count += 1

print("=" * 70)
print(f"Dynamic test summary: {pass_count} behaved as expected, {fail_count} did not")
print("=" * 70)
print("\nNote: some 'ACCEPTED' results above are EXPECTED to pass basic")
print("length/format validation. These are worth noting in the threat report:")
print("  - SQL-injection-style input is accepted, but is NOT exploitable")
print("    here because this app stores data in JSON files and never builds")
print("    a SQL query - the input is inert. This same string WOULD be a")
print("    serious risk if this app ever migrated to a SQL database.")
print("  - script-injection-style and whitespace-only input ARE accepted")
print("    and represent real, unaddressed gaps: validate_input() does not")
print("    strip whitespace or sanitize special characters at all.")
