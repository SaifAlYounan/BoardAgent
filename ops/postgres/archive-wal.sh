#!/bin/sh
set -eu

source_path=${1:?source WAL path is required}
wal_name=${2:?WAL name is required}

valid_hex_name() {
  case "$1" in
    *[!0-9A-F]* | "") return 1 ;;
    *) return 0 ;;
  esac
}

valid=false
case "$wal_name" in
  *.history)
    timeline=${wal_name%.history}
    if [ "${#timeline}" -eq 8 ] && valid_hex_name "$timeline"; then valid=true; fi
    ;;
  *.backup)
    prefix=${wal_name%.backup}
    segment=${prefix%.*}
    offset=${prefix##*.}
    if [ "${#segment}" -eq 24 ] && [ "${#offset}" -eq 8 ] && \
      valid_hex_name "$segment" && valid_hex_name "$offset"; then valid=true; fi
    ;;
  *)
    if [ "${#wal_name}" -eq 24 ] && valid_hex_name "$wal_name"; then valid=true; fi
    ;;
esac

if [ "$valid" != true ]; then
  echo "refusing unsupported WAL archive name" >&2
  exit 1
fi

destination=/wal-staging/$wal_name
temporary=$destination.partial.$$
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
umask 027

if [ -f "$destination" ]; then
  cmp -s -- "$source_path" "$destination"
else
  cp -- "$source_path" "$temporary"
  chmod 0640 "$temporary"
  sync -f "$temporary"
  if [ -f "$destination" ]; then
    cmp -s -- "$temporary" "$destination"
  else
    mv -- "$temporary" "$destination"
    sync -f /wal-staging
  fi
fi

# PostgreSQL may recycle its source only after the encryption sidecar has
# authenticated and durably published the off-host pair, signalled by deletion.
waited=0
while [ -f "$destination" ] && [ "$waited" -lt 120 ]; do
  sleep 1
  waited=$((waited + 1))
done
if [ -f "$destination" ]; then
  echo "encrypted WAL archive acknowledgement timed out" >&2
  exit 1
fi
