# Native 4gaBoards user-list captures

The JSON bodies are complete, unmodified responses from `GET /api/users` as the
ordinary native-reader account in genuine vendor images 3.3.8 and 3.3.9. The
parent's independent native probe captured them before module execution in run
`20261112T002047-a98c4f`. [provenance.json](provenance.json) records their hashes
and source request locations. All account/profile values are public lab fixtures.

Version 3.3.8 returns the administrator's private email, phone, organization and
SSO email. Version 3.3.9 returns only the other user's public five fields, while
retaining the requesting native-reader's own full profile. The source fix must
exclude that self profile before deciding whether another user's private data
was disclosed.

Unit examples run the real Framework loader, module initialization, URI builder,
JSON response parser and cleanup logic. HTTP delivery, generated password,
registration/admin/delete replies, loot storage and reporting are explicit
doubles. They prove reporting arguments and control flow, not authentication,
SQL persistence, target mutation or Docker behavior. The parent functional
suite supplies those separate controls. Synthetic response mutations are named
in their examples and do not alter these captured fixture files.
