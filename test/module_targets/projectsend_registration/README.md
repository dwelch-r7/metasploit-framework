# Native registration counterfactual

This diagnostic uses the existing pinned r1605 ProjectSend application/database
recipe and `projectsend_rce/native_probe.py` controls. It does not invoke a
Framework module or contribute a passing registered profile.

Use a disposable, natively installed runtime with `MODULE_TARGET_RUNTIME` set.
The regular native setup and `contain-mail` gate must already have passed; SMTP
must be contained at `127.0.0.1:9`. Supply a local JSON object containing only
`name`, `username`, `password`, `email`, and `address`, copied from the failed
registration. The username must contain an underscore; its dotted counterpart
must be 5–32 ASCII letters/digits/dots and neither account may already exist.

```sh
python3 -B test/module_targets/projectsend_registration/native_control.py /absolute/path/to/captured-case.json
```

The helper verifies both original backend source hashes in `vendor-files.json`,
invokes the original validator, and submits the same fields twice, changing only
underscores to dots in the username. It uses a real CSRF token for each request.
SQL row checks and genuine login distinguish rejected input from errors after
persistence. HTTP 500 after account creation is retained with available logs;
it is accepted only alongside the expected actual account and successful login.
The exact account and selected options are restored in `finally`, with a full
options/users/files/physical snapshot comparison. The caller must always tear
down and verify removal of its explicitly namespaced stack, including failures.

See the [dated result](../VERIFICATION-20261121-php-source-consumer.md). The
registration-response, username-generation and preservation issues remain open;
this control does not make the module green.
