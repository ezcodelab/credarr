#!/bin/sh
# LinuxServer conventions: start as root, become PUID:PGID, and make /config
# writable for that identity. Started with `--user` the ids are already the
# operator's and nothing needs changing.
#
# The app itself never runs as root: it is the one process that holds every
# stored credential, and a container root is one misconfigured bind mount away
# from owning the host's files.
set -eu

if [ "$(id -u)" = "0" ]; then
    PUID="${PUID:-1000}"
    PGID="${PGID:-1000}"

    if [ "$PGID" != "$(id -g credarr)" ]; then
        groupmod -o -g "$PGID" credarr
    fi
    if [ "$PUID" != "$(id -u credarr)" ]; then
        usermod -o -u "$PUID" credarr
    fi
    # HOME is the app user's own cache directory. Not recursive: anything
    # mounted under it belongs to the operator.
    chown credarr:credarr /home/credarr
    # A bind mount arrives owned by the host's ids. chown -R is the convention
    # for a volume this small (a database and its backups), and a silent
    # permission failure at first boot is worse than the walk.
    if [ -d /config ]; then
        chown -R credarr:credarr /config
    fi

    exec gosu credarr "$@"
fi

if [ -n "${PUID:-}" ] || [ -n "${PGID:-}" ]; then
    echo "warning: PUID/PGID are ignored: the container did not start as root" >&2
fi

exec "$@"
