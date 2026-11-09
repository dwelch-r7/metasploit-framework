# JBoss AS management targets

From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb jboss
```

The target is the original **JBoss AS 4.2.3.GA JDK6 distribution**, running on
digest-pinned Eclipse Temurin **8u412** (Linux amd64). The
[official JBoss download archive](https://jbossas.jboss.org/downloads.html)
links to the publisher's
[distribution and checksums](https://sourceforge.net/projects/jboss/files/JBoss/JBoss-4.2.3.GA/).
The archive must match its published SHA-256
`48797e150ee7dd6e035290fab86f17a5fe7d174b4980e941b833369b80273620`.
The Dockerfile extracts the distribution without replacing its servlets,
deployers, JMX implementation, or JSP compiler. The small benign WAR is built
with the pinned JDK's `jar` tool from the included JSP source.

The three genuine JBoss profiles differ only in management access policy:

| Service | JMX console | Status servlet | Public fixture credentials |
| --- | --- | --- | --- |
| `open` | Vendor default, unauthenticated | Vendor default, unauthenticated | Not required |
| `legacy` | Vendor-documented constraint covering GET and POST | All methods secured | `admin` / `module-target-admin-password` |
| `secured` | Constraint covering all methods | All methods secured | `admin` / `admin` |

`legacy` retains the historical method omission relevant to CVE-2010-0738.
On this release, a HEAD request reaches the management operation, then the
vendor RequestDispatcher returns 500 because of its response-wrapper check.
The independent controls require actual BSH file creation and repository JSP
execution/removal; that status alone does not prove execution. `jboss_vulnscan`
currently recognizes only a 200 HEAD bypass, so its 500 false negative remains
an explicitly recorded limitation. `secured` requires correct Basic credentials
even for HEAD. A genuine Apache service supplies unrelated HTTP negatives.
No RMI/JMX ports or reverse listeners are published on the host.
RMI/JNP retain their vendor default open policy inside the disposable network;
the `secured` profile qualifies HTTP authentication, not a fully hardened server.

Before Framework runs, a separate Ruby HTTP client and the vendor `twiddle`
CLI verify exact version/runtime, management policies, accepted/rejected
credentials, the real scanned paths, available deployment MBeans, BSH side
effects, repository deployment/removal, and two complete MainDeployer
deployment/removal cycles per profile. The native registry must restore after
each cycle. One benign app remains deployed as the declared baseline.

The 24 examples cover both scanners and the BSH/DeploymentFileRepository admin
modules. Status reads hold a real concurrent JSP request and compare the actual
client, virtual host and query to module output. Each admin path deploys the
native-built WAR twice, compares its SHA-256, executes the JSP, removes the WAR,
and checks both the deployment tree and live web-module registry. POST, GET,
legacy HEAD, authenticated POST, rejected credentials, unrelated HTTP and a
missing local WAR are exercised. Fresh deployer-created WARs are removed in an
explicit operator fallback only after assertions; this cannot turn a failed
module-cleanup assertion into a pass. JSP compilation caches are outside the
application deployment tree and are removed with the disposable container.
The missing-path case requires Framework's `OptPath` validation to reject the
input before module execution. Repository HEAD removal can emit an error after
the actual removal succeeds; its case requires independent file and registry
restoration twice instead of treating either a 500 or a success banner as proof.
The BSH HEAD path remains a strict failure if it stops after writing a stager
without deploying the final WAR.
`fixture/bsh-stager.jsp` is decoded byte for byte from the original failing
module's emitted request; its adjacent JSON records the capture and checksum.
Two independent native HEAD controls confirm that a parameterless GET reaches
that newly created stager without creating the destination WAR, then POST the
native-built archive and require its exact bytes, execution, and state cleanup.
The BSH helper can consult a caller's independent stager observation after 500;
500 without that proof remains a failure. HEAD cleanup responses remain
indeterminate until native file and registry observations establish restoration.

This profile does not qualify other AS/EAP releases, Java 17, native Windows or
Linux x86 payloads, TLS, alternate deployment directories, Seam applications,
serialized JMXInvokerServlet/Remoting exploits, or the post credential collector.
Java session deployment has a separate qualification scope; successful benign
WAR execution does not establish payload/session compatibility.

Only random host loopback HTTP ports are published. The shared runner owns a
fresh Compose project, isolated Framework configuration and retained evidence,
then removes that project's containers, network and volumes. See the
[shared guide](../README.md) for artifacts and cleanup commands. A lab definition
does not establish a passing result; inspect the strict run's `result.json`,
native captures, per-example console logs and teardown status.
The vendor RequestDumperValve records actual methods, queries, form parameters
and response statuses in retained target logs. Framework HttpTrace is disabled
for source uploads because literal JSP `catch(Exception ...)` text would trip
the shared console's runtime-exception guard; that guard remains unchanged.
