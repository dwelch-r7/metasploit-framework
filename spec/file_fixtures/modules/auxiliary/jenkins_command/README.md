# Jenkins command result captures

`responses.json` contains genuine responses from official digest-pinned Jenkins
2.442/JDK17 in the owned `test/module_targets/jenkins_command` lab. Provenance
includes raw capture paths and SHA-256 values. SystemInfo is reduced to its
actual headings and OS property rows; its ephemeral CSRF/cookie values are
replaced with fixed values. HTML command responses retain their actual `pre`
elements, while scriptText JSON bodies are retained unchanged as UTF-8.

The native recorder submits both the original module's Groovy and a result
envelope to the real controller with a valid session/crumb. Original quoted
arguments produce a genuine Groovy compilation error. Original HTML output
also contains literal `&lt;`, `out>` and `err>` text which the old parser alters.
The envelope captures retain actual stdout, stderr, integer exit status or an
operation failure message, including empty output and Unicode/dollar text.
Separate native `printf`, `id` and file-owner controls establish expected data.

The producer's source is the module's `command_script`: it uses Groovy's real
process APIs and `groovy.json.JsonOutput`, not a simulated protocol responder.
For reproduction, use the lab and submit that script to `/jenkins/scriptText`
with the CSRF field and session cookie from `/jenkins/systemInfo`. The official
[remote console documentation](https://www.jenkins.io/doc/book/managing/script-console/#remote-access)
describes the endpoint. The endpoint also exists in the actual
[Jenkins 1.638 source](https://github.com/jenkinsci/jenkins/blob/jenkins-1.638/core/src/main/java/jenkins/model/Jenkins.java#L3315).

Legacy crumb, header removal, missing OS, Windows property and malformed-result
examples are explicitly derived unit boundaries. They do not establish live
qualification of older Jenkins, Windows, proxies or malformed targets. No human
module Scenarios are created or changed.
