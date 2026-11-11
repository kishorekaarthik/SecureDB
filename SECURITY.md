# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/kishorekaarthik/SecureDB/security/advisories/new)
rather than opening a public issue. Include the affected version or commit, steps to
reproduce, and the impact you expect.

You can expect an acknowledgement within a week. Fixes for confirmed issues are released on
`main`, and reporters are credited unless they prefer otherwise.

## Scope

In scope: anything that lets one tenant read or change another tenant's data, recovers
plaintext or key material from the database alone, bypasses API key scopes or policies,
bypasses console authentication or CSRF protection, alters the audit log without detection by
`verify` with an anchor, or leaks values into logs or error responses.

Out of scope: attacks that require control of the running process, the master key or
database-owner credentials; network-level denial of service; and the `legacy-flask` branch,
which is kept only for history and is known to be insecure.

See the [threat model](docs/threat-model.md) for the full list of what is and is not defended.
