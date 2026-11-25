# Static typing pilot

Framework uses RBS signatures and Steep to check an explicit set of library
files. This is incremental checking: signatures describe the selected APIs,
and `Steepfile` selects the implementations and callers that are checked.

## Running the check

Use Ruby 3.3 or newer. From the repository root:

```sh
bundle install
bundle exec ruby tools/dev/check_types.rb
SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec test/typing/contracts_spec.rb
SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec spec/lib/rex/proto/dcerpc/uuid_spec.rb spec/lib/rex/proto/dcerpc/packet_spec.rb
```

RBS and Steep belong to the existing `:development, :test` group alongside
RuboCop, with `require: false`. They are available when either group is installed;
they are not runtime dependencies in the gemspec. There is one Framework
Gemfile and lockfile. GitHub Actions runs the check on Ruby 3.3 and 3.4, using
the same bundle exclusions as the test jobs. Framework requires Ruby 3.3 or
newer; Framework CI and RuboCop use that minimum. Generic reusable gem-testing
workflows retain their older Ruby lanes for other repositories.

The gate runs Steep with library-signature validation and rejects unsuccessful
analysis, missing UUID/Packet source coverage, any untyped calls, owned RBS
`untyped` declarations, and `untyped` annotations in checked Ruby files. Strict
diagnostics make incompatible assignments fail. Syntax, unsupported syntax and
internal checker errors also fail; fatal checker logs cannot be accepted just
because a process returned success. Ordinary comments mentioning untyped remain
legal. Raw `steep check` and `steep stats --format=csv --jobs=1` remain useful for
diagnosis, but a green raw check alone is not equivalent to passing this gate.

Keep `--validate=library`: the default validation scope can miss invalid
declarations that reopen dependency classes. During expansion, a duplicate
RubyGems declaration produced a green default check and an unexpectedly accepted
invalid caller. Library validation exposed the duplicate. RBS already supplies
RubyGems signatures; adding another copy was unnecessary.

## Checked libraries

The pilot checks a connected production path from DCERPC packet construction
through its UUID codec, alongside the existing utility/parser/mixin examples:

| Source | What it exercises | Typed calls |
| --- | --- | ---: |
| `lib/rex/ntpath.rb` | String coercion and Pathname | 6 |
| `lib/rex/version.rb` | Inheritance and a nullable constructor argument | 2 |
| `lib/rex/parser/ini.rb` | A parameterized Hash, mutable state, path coercion and file IO | 58 |
| `lib/rex/proto/dcerpc/uuid.rb` | Binary unpacking, tuples and nullable service lookups | 43 |
| `lib/rex/proto/dcerpc/packet.rb` | Actual codec callers, wire fields and fragmentation | 101 |
| `lib/rex/proto/ms_tds/ms_tds_login7_password.rb` | Byte arithmetic and an inherited BinData API | 35 |
| `lib/msf/core/exploit/retry.rb` | Generic block results and a mixin's required output method | 21 |

Steep 2.1.0 / RBS 4.2.0 reported 266 typed calls and zero untyped calls in this
sample. Counts apply only to these files, not their tests or other callers.
A typed call count does not prove the signatures, algorithm, binary encoding,
or runtime behavior are correct.

## The connected contract

`Packet.make_bind`, `make_bind_fake_multi`, `make_alter_context` and request
construction call the checked UUID methods. UUID wire-field locals have checked
String annotations: changing both the codec's implementation and its RBS return
type to Integer still fails at the real packet consumer. These annotations check
assignments; they are not assertions that override inference. This matters because
`Array#pack` itself accepts heterogeneous arrays and cannot prove their formats.

The committed `test/typing/contracts_spec.rb` copies real source, signatures and
configuration to temporary directories and deliberately breaks them. CI verifies
that invalid production calls, changed return contracts, missing APIs or
implementations, removed packet coverage, explicit type erasure, inferred untyped
calls and Ruby syntax errors are rejected. It also verifies valid callers, the
existing nullable/generic/visibility contracts, and rejection of a simulated
fatal checker result with exit status zero. The working checkout is not mutated.

Runtime packet specs independently verify wire bytes, bind/alter-context fields,
fragment flags and reassembly, object UUIDs, empty and 4000-byte boundaries, and
arbitrary binary/multibyte input. They reproduced character-count fragmentation
and infinite loops for nonpositive sizes. Requests now count bytes and reject
nonpositive sizes for nonempty payloads; empty requests still work with size zero.
Types do not establish those protocol properties: both defective and correct
implementations can manipulate Strings successfully.

## What expansion required

The pilot found a DCERPC UUID decoder bug: it counted characters instead of
the protocol's sixteen bytes. Tests reproduced rejection of valid bytes tagged
as UTF-8 and acceptance of oversized multibyte input. The decoder now normalizes
the encoding to binary before validating length. Type investigation prompted
these tests; the type system itself does not distinguish String encodings.

Other changes address checking limitations while preserving behavior:

- INI writing explicitly raises the existing TypeError when both paths are nil.
  Its signature accepts ordinary path-coercible objects, including Pathname.
- Password encoding uses `String#bytes` instead of `unpack('C*')`, giving the
  checker Integer elements without a cast. Runtime examples cover wire bytes,
  encoding, empty input and non-ASCII passwords.
- UUID unpacking has one trusted tuple assertion after the length guard.
  Retry exponentiation has one trusted Integer assertion because the retry
  count cannot be negative. Packet fragmentation has one trusted String slice
  assertion after positive-size and loop-bounds checks. These three invariants
  are not proved by Steep. Checked annotations for collections, UUID/version
  pairs and wire fields otherwise preserve checking instead of casting to pass.
- `typing/external/bindata.rbs` declares only the inherited surface used by the
  password field, based on the locked BinData and RubySMB sources. Dependencies
  and their generated field DSL are not checked. `get_parameter(:encode)` has
  type `top`, preserving its arbitrary result while permitting a truthiness
  check; this does not validate the parameter's value.
- `typing/external/rex_text.rbs` models the Integer-length `rand_text` call used
  for fake bind contexts. It is a partial dependency declaration; the gem's
  implementation and its output length are not proved by Steep.
- RBS cannot express Ruby's protected visibility. The INI signature uses private
  conservatively: external calls are rejected, but otherwise-valid protected
  calls on a peer would also be rejected. Runtime visibility remains protected
  and is covered by a spec. The retry mixin uses an interface self type for `vprint_status`, rather
  than declaring a pretend implementation on the mixin.
- Strict checking misses the INI class's attribute/alias implementations.
  Only that class retains non-failing missing-implementation diagnostics;
  its focused runtime specs cover those methods. Protocol methods treat missing
  implementations as errors. Other strict assignment checks remain enabled.

Checked-file caller probes also verify rejection of invalid input types,
unguarded nullable lookups, and an invalid operation on an inferred retry result.
These probes matter: a green implementation check alone does not establish
useful caller contracts. Runtime specs remain necessary for errors, encodings,
protocol semantics and behavior supplied by dependencies.

## Wider adoption

An exploratory November 2026 check widened the source selection to all 2,330
Ruby files under `lib/`, with the pilot signatures and no generated project-wide
stubs. It produced roughly 91,000 diagnostics across about 2,300 files, dominated
by unknown constants and missing methods. This measures missing declarations
and context as well as potential defects; it is not a count of runtime bugs or
an estimate of migration hours. Steep also logged internal errors on some
legacy constructs, so this run does not establish complete analysis of every
file. Saving diagnostics with `--save-expectations` returns success even when
diagnostics exist; that mode is for measurement, not the enforced CI check.

Start with cohesive library boundaries that have focused tests and stable
inputs and outputs. Add both implementations and a few real callers, so typed
islands grow into useful checked paths. Protocol codecs and parsers offer clear
contracts, but encoding, lengths and intentionally malformed packets need runtime
tests. Framework mixins need explicit host interfaces. Large option/data-store
hierarchies, Rails code and generated BinData records need dependency signatures
and conventions before they make good mandatory targets.

Require signatures for new APIs inside a checked boundary, and maintain existing
ones when those APIs change. Do not require every new file or every touched old
file across Framework to become typed immediately. Keep exploit, auxiliary,
post and payload modules outside mandatory checking initially. Library API
signatures can later support optional module checking without requiring every
module contributor to maintain type infrastructure.

For human contributors, useful contracts make nullable results, block returns
and dependencies easier to understand and refactor. The costs are another
language/tool, signatures that can drift, dependency bridges, inference limits
and an extra CI step. For AI agents, checked APIs constrain invented methods
and incompatible arguments and provide fast feedback. Agents must read the
signatures, include relevant caller files in the check, run it, and still run
runtime tests. Generating broad `untyped` stubs or adding assertions until CI is
green can hide mistakes and create false confidence for both audiences.

## Scope and contribution

Only files listed with `check` in `Steepfile` have their Ruby implementations
checked. A signature alone does not check a caller in another file. Modules,
plugins, and other libraries are outside the pilot; adding or editing them
does not require signatures. Continue running the relevant RSpec examples:
static types do not verify path normalization or other runtime behavior.

For a change to a checked API, update the signature and implementation together
and run Steep. To extend coverage, add signatures under `typing/` and explicitly
add the relevant source and caller files to `Steepfile`. Review input coercions,
nullable results, dependency declarations, and every assertion or `untyped`
escape hatch; a passing check can still contain unchecked operations. Do not
rewrite a hot path solely to satisfy inference without checking its behavior
and performance.

Signatures are development-only under `typing/`, rather than automatically
discovered gem signatures under `sig/`: they describe only the pilot's APIs.
They do not yet provide general Framework completion or checking for module
authors. Keep expansion incremental so a module contribution does not acquire
a Framework-wide typing requirement.
