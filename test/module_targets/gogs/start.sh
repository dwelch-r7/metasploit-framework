#!/bin/sh
set -eu

# The authentic vendor entrypoint establishes git/PUID/PGID and /data first.
test "$(id -u)" = 0
test "$(id -u git)" = 1000
export USER=git HOME=/home/git GOGS_CUSTOM=/data/gogs
cd /app/gogs
version=$(/app/gogs/gogs --version)
case "$version" in
  "Gogs version ${GOGS_LAB_VERSION}"*) ;;
  *) printf 'Unexpected Gogs version: %s\n' "$version" >&2; exit 1 ;;
esac
mkdir -p /data/gogs/conf /data/gogs/data /data/gogs/log /data/git/gogs-repositories
cat > /data/gogs/conf/app.ini <<CONFIG
BRAND_NAME = Module target Gogs
RUN_MODE = prod
RUN_USER = git

[server]
EXTERNAL_URL = ${GOGS_LAB_EXTERNAL_URL}
DOMAIN = ${GOGS_LAB_HOST}
HTTP_ADDR = 0.0.0.0
HTTP_PORT = 3000
DISABLE_SSH = true
APP_DATA_PATH = /data/gogs/data
OFFLINE_MODE = true
DISABLE_ROUTER_LOG = false

[database]
TYPE = sqlite3
PATH = /data/gogs/gogs.db

[repository]
ROOT = /data/git/gogs-repositories
SCRIPT_TYPE = bash
DEFAULT_BRANCH = master
DISABLE_HTTP_GIT = false
MAX_CREATION_LIMIT = -1
COMMITS_FETCH_CONCURRENCY = 1

[security]
INSTALL_LOCK = true
SECRET_KEY = Module-target-public-artificial-Gogs-secret-2026

[auth]
DISABLE_REGISTRATION = true

[email]
ENABLED = false

[session]
PROVIDER = memory

[log]
ROOT_PATH = /data/gogs/log
MODE = console
LEVEL = Trace
CONFIG
chown -R git:git /data
if ! test -e /data/gogs/.module-target-initialized; then
  if test -e /data/gogs/gogs.db; then
    printf 'Incomplete lab initialization: preserve the owned database for diagnosis\n' >&2
    exit 1
  fi
  # The admin CLI's SetEngine initializes only its new tables. The genuine web
  # path calls NewEngine, migrates and synchronizes the remaining vendor tables.
  # See internal/{db,database}/models.go and internal/route/install.go upstream.
  # Port 3001 is unexposed; Compose probes 3000 only after all six users exist.
  bootstrap_pid=
  bootstrap_spawn_pending=false
  stop_bootstrap() {
    test -n "$bootstrap_pid" || return 0
    bootstrap_stopping_pid=$bootstrap_pid
    if ! kill -TERM "$bootstrap_stopping_pid"; then
      if wait "$bootstrap_stopping_pid"; then bootstrap_exit=0; else bootstrap_exit=$?; fi
      bootstrap_pid=
      printf 'Bootstrap exited before requested termination (status %s)\n' "$bootstrap_exit" >&2
      return 1
    fi
    # Observe real process exit/zombie state before wait; a stuck process is
    # killed explicitly rather than escaping the fixture's error/signal trap.
    if timeout 10 sh -c '
      while test -r "/proc/$1/stat"; do
        if ! read -r observed_pid observed_name observed_state observed_rest < "/proc/$1/stat"; then exit 0; fi
        case "$observed_state" in Z|X) exit 0 ;; esac
        sleep 0.1
      done
    ' sh "$bootstrap_stopping_pid"; then
      bootstrap_forced=false
    else
      bootstrap_forced=true
      printf 'Bootstrap did not terminate within 10 seconds; killing owned PID %s\n' "$bootstrap_stopping_pid" >&2
      if ! kill -KILL "$bootstrap_stopping_pid"; then
        printf 'Could not kill bootstrap PID %s; collecting its exit status\n' "$bootstrap_stopping_pid" >&2
      fi
    fi
    if wait "$bootstrap_stopping_pid"; then bootstrap_exit=0; else bootstrap_exit=$?; fi
    bootstrap_pid=
    printf 'Bootstrap termination status %s (TERM requested; forced=%s)\n' "$bootstrap_exit" "$bootstrap_forced"
    test "$bootstrap_forced" = false || return 1
    case "$bootstrap_exit" in
      0|143) return 0 ;;
      *) printf 'Unexpected bootstrap process exit: %s\n' "$bootstrap_exit" >&2; return 1 ;;
    esac
  }
  bootstrap_cleanup() {
    bootstrap_original_exit=$1
    trap - EXIT HUP INT TERM
    # A signal between spawning and assigning $! still owns that last child.
    if test "$bootstrap_spawn_pending" = true; then bootstrap_pid=${!:-}; fi
    if ! stop_bootstrap; then
      test "$bootstrap_original_exit" != 0 || bootstrap_original_exit=1
    fi
    exit "$bootstrap_original_exit"
  }
  trap 'bootstrap_cleanup "$?"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  bootstrap_spawn_pending=true
  gosu git /app/gogs/gogs web --port 3001 --config /data/gogs/conf/app.ini &
  bootstrap_pid=$!
  bootstrap_spawn_pending=false
  if timeout 60 sh -c '
    until curl --fail --silent --max-time 2 http://127.0.0.1:3001/ >/dev/null 2>&1; do
      kill -0 "$1" 2>/dev/null || exit 1
      sleep 0.2
    done
  ' sh "$bootstrap_pid"; then
    printf 'Native web schema bootstrap became ready on unexposed port 3001\n'
  else
    bootstrap_readiness_exit=$?
    printf 'Native web schema bootstrap readiness failed (status %s)\n' "$bootstrap_readiness_exit" >&2
    exit 1
  fi
  stop_bootstrap
  while IFS="$(printf '\t')" read -r username password email administrator; do
    test "$username" != username || continue
    set -- admin create-user --name "$username" --password "$password" --email "$email" --config /data/gogs/conf/app.ini
    if test "$administrator" = true; then set -- "$@" --admin; fi
    gosu git /app/gogs/gogs "$@"
  done < /opt/module-target-gogs-accounts.tsv
  touch /data/gogs/.module-target-initialized
  chown git:git /data/gogs/.module-target-initialized
  trap - EXIT HUP INT TERM
fi
exec gosu git /app/gogs/gogs web --config /data/gogs/conf/app.ini
