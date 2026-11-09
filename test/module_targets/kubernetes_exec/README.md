# Kubernetes execution profile

Run the genuine [K3s target](../kubernetes/README.md):

~~~sh
bundle exec ruby tools/dev/run_module_target_tests.rb kubernetes_exec
~~~

This separate bounded profile covers direct commands, interactive WebSocket
shells, Linux droppers, Python Meterpreter, real session-based configuration and
routing, discovered/explicit pod images, invalid/denied access, missing pods and
empty image discovery. The created-pod path intentionally retains the module's
documented operator cleanup; assertions verify that state before deleting it.
