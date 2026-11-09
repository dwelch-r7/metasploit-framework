# JBoss Java session qualification

The selected checkpoint covers **114 runtime modules, 50 families and 718
functional cases**, with exact counts, zero failures/pending/outside errors,
matching current recorded hashes and owned teardown for every selected profile.
This adds two modules and twelve cases to the
[preceding checkpoint](VERIFICATION-20261109-consul-execution.md). The broader
goal remains active. No PR was created or full local RSpec suite run.

The [session lab](jboss_deployer/README.md) exercises genuine JBoss AS 4.2.3.GA
on Temurin 8u412 Linux amd64. Both `jboss_bshdeployer` and
`jboss_deploymentfilerepository` open actual Java Meterpreter and command-shell
sessions with default Spawn=2. Direct POST, GET stagers, legacy HEAD stagers,
authenticated POST, automatic Java fallback and explicit Java Universal paths
are covered. Each positive path requires two fresh sessions, a newly created
target file with native owner proof, and exact restoration of the WAR/stager
tree and live vendor deployment registry. Wrong credentials and unrelated HTTP
must not create a session or application. Sixteen sessions passed these checks.

## Target failure and correction

The original `20261109T202225-6fcfcd/jboss_deployer` completes **12/2** in
450.562006 seconds. Its twelve explicit-target sessions succeed. Both automatic
cases receive HTTP 500 before deployment: the untouched vendor inspector JSP
cannot compile against Java 8 with its packaged old Eclipse JDT. Independent
GET and POST reproduce the compiler error; vendor CLI attributes remain usable.
This establishes a fixture/runtime compatibility gap rather than a module defect.

The session-only fixture selects Jasper's documented Ant/javac compiler option,
forked JDK 8 javac and aligned source/target 1.5. Apache Ant 1.10.15 is verified
against its publisher SHA-512. Independent preflight checks verify compiler
configuration and Ant version, compare GET/POST inspector fields with the live
vendor CLI on all three policies, and hash the unchanged inspector JSP,
JBossWeb jar and original JDT jar against the official archive. The management
family's default compiler and all 47 selected inputs remain unchanged.

The corrected `20261109T205412-8f1241/jboss_deployer` completes **12/0** in
519.294172 seconds, with zero pending/outside errors and owned teardown passed.
Native management controls record 85 commands and 747 HTTP observations; the
additional inspector gate records twelve commands and six HTTP requests.
Polling counts are observations, not unique coverage counts. No production
source, functional assertion, payload setting or shared runner timeout changed.
No operator fallback cleanup was needed.

## Retention and limits

All 54 final recorded inputs match the integrated source. The original 50-file
input set is also retained: three fixture files were reconstructed by reversing
the correction and matching the immutable original hashes; the other 47 were
copied unchanged. This is explicitly recorded as reconstruction. The final set
adds four fixture files and changes three fixture inputs.

The parent imported and byte-checked all 54 regular evidence files, including
hidden metadata snapshots, and independently verified all 403 export checksums
in `jboss-session-20261109-b5c6fd199b5`. Both runner projects and the final
compiler-jar volume audit absent. New/changed session Ruby files lint clean;
resolved Compose, shell syntax and the twelve-case dry run pass. The preceding
75 focused JBoss checks remain separately recorded rather than recounted here.

Other AS/EAP/JDK releases, architectures, native Windows/Linux x86 delivery,
TLS, alternate contexts and serialized invoker/Remoting paths remain
unqualified. Vendor HEAD cleanup responses retain their HTTP 500 ambiguity;
native filesystem/registry restoration supplies the evidence in these cases.
Java 8 Spawn=2 success does not resolve the separate Tomcat/Java 17 payload issue.

Aggregate selector: `tmp/module-target-checkpoint-jboss-session-current.json`.
Its sole warning names the unqualified WordPress admin reproducer. Hashes cover
selected inputs, not the entire dependency graph. Ansible deployment and Linux
credential-file collection retain separate investigations. Fork CI must be
assessed independently; no overall green-CI claim is made.
