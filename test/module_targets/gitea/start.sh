#!/bin/sh
set -eu

if [ "$(id -u)" = 0 ]; then
  mkdir -p /data/gitea/conf /data/git/repositories
  chown -R git:git /data
  exec su-exec git:git /bin/sh "$0"
fi

test "$(id -un)" = git
. /opt/module-target-gitea-accounts.env
export USER=git HOME=/data/git GITEA_CUSTOM=/data/gitea
cd /app/gitea
mkdir -p /data/gitea/log /data/gitea/indexers /data/gitea/avatars
root_url=${GITEA_LAB_ROOT_URL:-"http://${GITEA_LAB_HOST}:3000/"}
cat > /data/gitea/conf/app.ini <<EOF
APP_NAME = Module target Gitea
RUN_MODE = prod
RUN_USER = git

[server]
DOMAIN = ${GITEA_LAB_HOST}
HTTP_ADDR = 0.0.0.0
HTTP_PORT = 3000
ROOT_URL = ${root_url}
DISABLE_SSH = true
APP_DATA_PATH = /data/gitea

[database]
DB_TYPE = sqlite3
PATH = /data/gitea/gitea.db

[repository]
ROOT = /data/git/repositories

[security]
INSTALL_LOCK = true
DISABLE_GIT_HOOKS = ${GITEA_LAB_DISABLE_HOOKS:-false}

[service]
DISABLE_REGISTRATION = true

[migrations]
ALLOW_LOCALNETWORKS = ${GITEA_LAB_ALLOW_LOCAL_NETWORKS:-true}
ALLOWED_DOMAINS = ${GITEA_LAB_ALLOWED_DOMAINS-*}

[indexer]
ISSUE_INDEXER_TYPE = db

[log]
MODE = console
LEVEL = Info
ROOT_PATH = /data/gitea/log

[other]
SHOW_FOOTER_VERSION = true
EOF

gitea --config /data/gitea/conf/app.ini migrate
case "$(gitea --version)" in
  'Gitea version 1.12.6 '*) set -- admin create-user ;;
  'Gitea version 1.16.'*) set -- admin user create ;;
  *) printf 'Unexpected native Gitea version\n' >&2; exit 1 ;;
esac
gitea --config /data/gitea/conf/app.ini "$@" --username "$LAB_ADMIN" --password "$LAB_PASSWORD" --email "admin@$LAB_EMAIL_DOMAIN" --admin --must-change-password=false
gitea --config /data/gitea/conf/app.ini "$@" --username "$LAB_USER" --password "$LAB_PASSWORD" --email "user@$LAB_EMAIL_DOMAIN" --must-change-password=false
exec gitea --config /data/gitea/conf/app.ini web
