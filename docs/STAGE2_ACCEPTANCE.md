# Stage 2 acceptance scenarios

The focused regression tests cover device revocation during a live PTY and command, account removal, and permission changes. Final integrated acceptance should also exercise:

- Revocation during large uploads and downloads, including an interrupted partial file and a subsequent login with reduced rights.
- Revocation while TCP tunnels carry traffic and while directory operations are in flight; confirm that the remote socket and helper process close.
- Revocation during UDP → TCP and direct TCP → relay recovery, including a RESUME racing with the authorization-file update.
- Several concurrent sessions for one key and account, plus unaffected sessions belonging to other keys and accounts.
- Repeated authorization-file replacement, malformed or unreadable files, and restoration after revocation; old session IDs must remain unusable.
- Termination of a foreground command and a PTY process group that has background descendants, with no post-revocation side effects.

An authorization change ends the existing session rather than expanding its rights in place. A new login is required to receive the current rights. A running session is checked at most 200 ms after an authorization-file change; authorization is also checked synchronously before RESUME.
