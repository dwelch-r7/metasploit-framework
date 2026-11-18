# Apache Airflow example DAG targets

Controlled targets for the legacy example DAG. Native prerequisites run before
public module calls. No fixture HTTP handler replaces Airflow.

The pinned official 1.10.10 and 1.10.11 amd64 images run as UID 50000. Only the
stock `example_trigger_target_dag` is copied into the configured DAG directory.
The normal password-authentication extra is installed offline from a pinned
Flask-Bcrypt source archive, using dependencies already in the vendor image.
SQLite and SequentialExecutor keep the webserver, scheduler and real Bash/Python
tasks in one application container. A separate capped PostgreSQL service stores
Framework reports. Both ports bind to localhost.

Prepare the tiny password-wrapper build context, then run profiles serially:

```sh
python3 test/module_targets/airflow_dag/prepare.py
MODULE_TARGET_NAMESPACE=airflow-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb airflow_dag airflow_dag_fixed airflow_dag_denied airflow_dag_missing airflow_dag_patched airflow_dag_prefix
```

The guarded launcher serializes participating worktrees and removes each stack
and its volumes when finished. App limits: 1 CPU, 1024 MiB, 128 PIDs. Reporting
limits: 0.25 CPU, 384 MiB, 128 PIDs. Only these two containers run for a profile.
Use a distinct namespace; clean only resources created under that namespace.
Completed probes are removed immediately; remove task-owned containers left
unused for over one hour. Never use a global Docker prune for this fixture.

Profiles cover the stock vulnerable release, full fixed release, native
`deny_all` API authentication, an empty configured DAG directory, the unmodified
vendor fixed DAG backported to 1.10.10, and the native `/airflow` URL prefix.
Password authentication protects the UI while the explicitly configured legacy
experimental API is open, except in the denied profile. All credentials and the
Flask secret are disposable fixture values.

Native controls verify a real valid/invalid UI login, deployed DAG checksums,
API responses, scheduler heartbeat and terminal task states. Normal DAG runs and
command-injection contrasts distinguish a functional target from an HTTP-only
setup. Tests track concrete execution dates, close real sessions, remove proof
files and reset only observed terminal runs through the real ORM. Resetting the
paused flag and deleting run metadata/logs is explicit fixture cleanup; the
owning exploit leaves those target artifacts for its operator.

Source provenance: [Apache's 1.10.10 example DAG](https://github.com/apache/airflow/blob/1.10.10/airflow/example_dags/example_trigger_target_dag.py),
[the 1.10.11 fixed DAG](https://github.com/apache/airflow/blob/1.10.11/airflow/example_dags/example_trigger_target_dag.py),
and [the documented historical password extra](https://airflow.apache.org/docs/apache-airflow/1.10.15/security.html).
The fixture ships the fixed Python source unmodified, with its checksum in
`profiles.json`; it does not ship an opaque application binary.

AutoCheck-disabled session repeats start with the DAG re-paused by fixture
cleanup. The exploit must initialize that state itself; tests do not pre-unpause
it to conceal a dependency on an earlier check.
