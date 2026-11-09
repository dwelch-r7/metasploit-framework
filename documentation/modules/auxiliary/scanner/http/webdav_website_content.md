## Description

This auxiliary module scans a host or range of hosts for servers that disclose their content via WebDav.

## Automated local targets

The [managed Apache WebDAV lab](../../../../../test/module_targets/webdav/README.md)
provides real services and independent native controls. Run
`bundle exec ruby tools/dev/run_module_target_tests.rb webdav` from the
repository root. See the lab guide and campaign for qualification results,
known failures and remaining limits.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/webdav_website_content```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Options

### DEPTH

The default `1` lists the requested collection and its immediate children.
Use `0` to request only the collection itself. `infinity` requests recursive
content when the server permits it; Apache commonly refuses that depth.
Earlier versions omitted the Depth header, which implicitly requested infinity.
Set `DEPTH infinity` to retain that request scope. The historical scenario below
shows recursive results; its console output has not been regenerated.

## Scenarios

```
msf > use auxiliary/scanner/http/webdav_website_content
msf auxiliary(webdav_website_content) > set RHOSTS 192.168.1.201
RHOSTS => 192.168.1.201
msf auxiliary(webdav_website_content) > run

[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/aspnet_client/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/images/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_private/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_cnf/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_cnf/iisstart.htm
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_cnf/pagerror.gif
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_log/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/access.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/botinfs.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/bots.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/deptodoc.btr
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/doctodep.btr
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/frontpg.lck
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/linkinfo.btr
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/service.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/service.lck
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/services.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/svcacl.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/uniqperm.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_pvt/writeto.cnf
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_script/
[*] Found file or directory in WebDAV response (192.168.1.201) http://192.168.1.201/_vti_txt/
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(webdav_website_content) >
```
