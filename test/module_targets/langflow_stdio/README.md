# Langflow MCP stdio execution target

The primary profile runs official Langflow 1.8.4 with automatic login disabled.
The comparison profile uses official 1.9.0. Both images are digest-pinned; the
backend runs as UID 1000 with one CPU, 3 GiB memory, 256 PIDs and one worker.
The public-console lane runs three capped containers at a time.

Run `bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_stdio langflow_stdio_fixed`.
The profiles execute serially, starting with a cold console. Teardown removes
owned containers, networks and volumes.

Native controls create an active ordinary account and verify `is_superuser`
is false. Module operations use that account. An SDK-based stdio server exposes
one real echo tool; its source is mounted read-only without replacing any
application endpoint. The native probe verifies the installed packages and
eight installed source hashes. Automatic project-to-MCP registration is
disabled with the supported `LANGFLOW_ADD_PROJECTS_TO_MCP_SERVERS=false`
setting, which the probe verifies. Explicit SDK control definitions in both
users' registries must remain identical across public operations.

Independent encoded canaries verify that registration itself does not execute
code, while each tool-count listing does execute it on 1.8.4. On 1.9.0 the API
rejects inline Python, including a separate minimal `-c pass` control, while
accepting and running the legitimate stdio server. These tests qualify the
module's REST configuration path; other MCP execution surfaces are separate.

Functional checks require exact command effects, used shell/Meterpreter
sessions, both Meterpreter fork settings, live backend health, correct database
origin and closure, original process restoration, and preservation of both
users' MCP registries. Nonforked Meterpreter must remain usable beyond the
configured MCP discovery deadline before shutdown. Each public operation is
repeated on the same selected module. Results and limitations are recorded in
the checkpoint report.
