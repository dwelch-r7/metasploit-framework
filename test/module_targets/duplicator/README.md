# Duplicator file-read target

Runs the genuine official Duplicator 1.3.24 and 1.3.26 plugins and the fixed
1.3.28 plugin on pinned WordPress 5.2.4/PHP 7.3.11 and MariaDB 11.2.2.
Official 1.3.27 ZIP and SVN URLs returned 404 during source acquisition; that
release is not represented by a runtime profile.

Prepare the checksum-pinned archives with
`DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/duplicator/prepare.rb`.
Then run `DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb duplicator duplicator_minimum duplicator_prefix duplicator_fixed duplicator_absent duplicator_unrelated`.
The guarded launcher runs one stack at a time and removes each stack's containers
and volumes. Root and subdirectory profiles have two capped containers; the
unrelated HTTP profile has one. Ports bind only to loopback.

The preflight verifies installed ZIP/source hashes, normal WordPress login,
accounts and file hashes, then independently probes the native download route.
Tests use public console check/run dispatch and compare actual loot bytes with
the independent target files. The quoted-path control is a native refusal: the
legacy plugin retains WordPress's added slash. Empty file downloads have genuine
attachment headers and are distinct from the plugin's HTTP 200 error bodies.
The fixed preflight also uses Duplicator's package persistence API and a
fixture SQL marker to prove a legitimate ID/hash download still works. It does
not build a full backup. No vendor request handler is replaced. Fixtures contain only owned local data.

The existing module guide and its human Scenarios remain unchanged.
