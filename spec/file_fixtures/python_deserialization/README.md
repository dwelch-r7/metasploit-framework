# Python deserialization execution contracts

`execute.py` is a bounded standard-library Python driver for the focused Ruby
spec. It loads the actual generated pickle, runs real `Thread` and builtin `exec`,
captures actual worker exceptions through `threading.excepthook`, and joins/reaps
workers. It does not use a transport, thread or interpreter double.

Run `bundle exec rspec spec/lib/msf/util/python_deserialization_spec.rb` with
Python 3.8 or newer available as `python3`, or select an existing interpreter with
`PYTHON=/path/to/python3`. No additional Python package is needed.

The registry/decorator example preserves the relevant `EXPORTED_SYMBOLS` and
`export` structure from Python Meterpreter. Real pgAdmin 8.3 / Python 3.11 target
logs on 18 November 2026 show its decorator raising `NameError` from `Thread.run`.
The unit also runs that structure through Framework's real compressed exec stub.
These are benign namespace controls; they open no callback or Meterpreter session.

For reference-generator equivalence, the driver replaces only its literal
`'#{escaped}'` template with the controlled test code before running the real
generator. Its pickle then executes through the same real interpreter driver.
Exact memo-number bytes are not portable between Python pickler versions, so
the contract compares behavior. Native pgAdmin execution and other consuming
products require their separate functional qualification.
