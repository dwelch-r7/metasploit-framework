# Serial Erlang cookie old release profile

Run both genuine pinned RabbitMQ/OTP release profiles serially:

```sh
MODULE_TARGET_NAMESPACE=my-erlang-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb erlang_cookie_old erlang_cookie_new
```

The [shared fixture](../erlang_cookie/README.md) supplies the original owner and
native distribution/RPC controls. This profile selects only `old`. Docker
init reaps orphaned native/payload children, as a normal host init would.
The initial broker/native-client/Framework stack has three capped containers;
the completed native client is removed before owning module calls, leaving two.
No reporting database is used. Complete projects and anonymous volumes are
removed between releases, including on interruption.

The nine cases cover repeated 13/255/256/65535-byte commands, exact rich command
bytes, the explicit 65536-byte refusal, incorrect cookies, Bash sessions and a
Linux x64 printf Meterpreter stager. Native stock-handler controls gate each
session family; public session APIs prove actual UID/PID/files and graceful
shutdown with physical PID disappearance. The same owner paths run twice.
Stock tool metadata separately records availability of telnet, required by the
owner's default command payload. These cases explicitly choose Bash; they do not
qualify the telnet default. Windows, Linux x86, other stagers, releases, network
layouts and full ancestor-process preservation remain open.
