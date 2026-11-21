# Static typing pilot

Framework uses RBS signatures and Steep to check an explicit set of library
files. The first target is `lib/rex/ntpath.rb`, a small utility used by SMB
sessions with existing RSpec coverage and only standard-library dependencies.
The pilot checks its implementation against `typing/rex/ntpath.rbs` without
changing the Ruby code.

## Running the check

Use Ruby 3.3 or newer. From the repository root:

```sh
BUNDLE_GEMFILE=gemfiles/typing.gemfile bundle install
BUNDLE_GEMFILE=gemfiles/typing.gemfile bundle exec steep check --no-daemon --jobs=1
```

The separate bundle installs only the typing tools and their dependencies.
The normal Framework bundle and supported runtime versions are unchanged.
GitHub Actions runs this check on Ruby 3.3 and 3.4 for pull requests and pushes
to `master`.

## Scope and contribution

Only files listed with `check` in `Steepfile` have their Ruby implementations
checked. A signature alone does not check a caller in another file. Modules,
plugins, and other libraries are outside the pilot; adding or editing them
does not require signatures. Continue running the relevant RSpec examples:
static types do not verify path normalization or other runtime behavior.

For a change to a checked API, update the signature and implementation together
and run Steep. To extend coverage, choose another small library with focused
tests, add its signature under `typing/`, and explicitly add its source file to
`Steepfile`. Review input coercions, nullable results, and any casts or `untyped`
escape hatches; a passing check can still contain unchecked operations.

Signatures are development-only under `typing/`, rather than automatically
discovered gem signatures under `sig/`: they describe only the pilot's APIs.
They do not yet provide general Framework completion or checking for module
authors. Keep expansion incremental so a module contribution does not acquire
a Framework-wide typing requirement.
