# shellcheck shell=bash
# Shared by backup.sh, restore.sh and restore-drill.sh; sourced, not run.
#
# How a backup set is encrypted, and how its files are read back:
#
#   BACKUP_AGE_RECIPIENT    an age public key (age1...). Needs `age`. The
#                           matching identity file is needed only to restore,
#                           and should not be kept on this machine.
#   BACKUP_GPG_RECIPIENT    a key in root's GnuPG keyring, by id or email.
#   BACKUP_PASSPHRASE_FILE  a root-only file holding a passphrase; symmetric
#                           AES-256 with gpg, or with openssl where gpg is
#                           not installed. age cannot read a passphrase
#                           without a terminal, so it is not used for this.
#
# The first one set wins. A public key is the better choice: the server can
# then write backups it cannot read, so someone who takes the server does not
# get the older sets with it.

# A setting from the environment (the systemd unit loads .env) or, when run
# by hand, straight from .env.
setting() {
  local value=${!1:-}
  if [[ -z "$value" && -f .env ]]; then
    value=$(sed -n "s/^$1=//p" .env | tail -n 1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/')
  fi
  printf '%s' "$value"
}

# Sets ENC_METHOD (none, age, gpg, gpg-symmetric, openssl) and ENC_EXT.
encryption_method() {
  AGE_RECIPIENT=$(setting BACKUP_AGE_RECIPIENT)
  GPG_RECIPIENT=$(setting BACKUP_GPG_RECIPIENT)
  PASSPHRASE_FILE=${PASSPHRASE_FILE:-$(setting BACKUP_PASSPHRASE_FILE)}
  ENC_METHOD=none ENC_EXT=""
  if [[ -n "$AGE_RECIPIENT" ]]; then
    command -v age >/dev/null 2>&1 || { echo "BACKUP_AGE_RECIPIENT is set but age is not installed (apt install age)" >&2; return 1; }
    ENC_METHOD=age ENC_EXT=.age
  elif [[ -n "$GPG_RECIPIENT" ]]; then
    command -v gpg >/dev/null 2>&1 || { echo "BACKUP_GPG_RECIPIENT is set but gpg is not installed" >&2; return 1; }
    ENC_METHOD=gpg ENC_EXT=.gpg
  elif [[ -n "$PASSPHRASE_FILE" ]]; then
    [[ -r "$PASSPHRASE_FILE" ]] || { echo "BACKUP_PASSPHRASE_FILE ($PASSPHRASE_FILE) cannot be read" >&2; return 1; }
    if command -v gpg >/dev/null 2>&1; then
      ENC_METHOD=gpg-symmetric ENC_EXT=.gpg
    else
      ENC_METHOD=openssl ENC_EXT=.enc
    fi
  fi
}

encrypt_file() {  # encrypt_file <file>: writes <file><ext>, removes <file>
  local file=$1
  case "$ENC_METHOD" in
    age) age -r "$AGE_RECIPIENT" -o "$file$ENC_EXT" "$file" ;;
    gpg) gpg --batch --yes --quiet --trust-model always -r "$GPG_RECIPIENT" -o "$file$ENC_EXT" -e "$file" ;;
    gpg-symmetric)
      gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-file "$PASSPHRASE_FILE" \
        --cipher-algo AES256 -o "$file$ENC_EXT" -c "$file" ;;
    openssl)
      openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$PASSPHRASE_FILE" \
        -in "$file" -out "$file$ENC_EXT" ;;
  esac
  rm -f "$file"
}

# plain <backup dir> <name>: the file's plaintext on standard output, whether
# it was stored as <name>, <name>.age, <name>.gpg or <name>.enc. Uses
# AGE_IDENTITY (restore's --identity) and PASSPHRASE_FILE.
plain() {
  local dir=$1 name=$2
  if [[ -f "$dir/$name" ]]; then
    cat "$dir/$name"
  elif [[ -f "$dir/$name.age" ]]; then
    [[ -n "${AGE_IDENTITY:-}" ]] || { echo "$name.age needs --identity <age identity file>" >&2; return 1; }
    age -d -i "$AGE_IDENTITY" "$dir/$name.age"
  elif [[ -f "$dir/$name.gpg" ]]; then
    if [[ -n "${PASSPHRASE_FILE:-}" ]]; then
      gpg --batch --quiet --pinentry-mode loopback --passphrase-file "$PASSPHRASE_FILE" -d "$dir/$name.gpg"
    else
      gpg --batch --quiet -d "$dir/$name.gpg"
    fi
  elif [[ -f "$dir/$name.enc" ]]; then
    [[ -n "${PASSPHRASE_FILE:-}" ]] || { echo "$name.enc needs --passphrase-file <file>" >&2; return 1; }
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$PASSPHRASE_FILE" -in "$dir/$name.enc"
  else
    return 1
  fi
}

has() {  # has <backup dir> <name>: stored in any form
  local ext
  for ext in "" .age .gpg .enc; do [[ -f "$1/$2$ext" ]] && return 0; done
  return 1
}

# Every file the manifest lists must be present with the recorded SHA-256.
verify_manifest() {
  local dir=$1 name sum failed=0
  [[ -f "$dir/MANIFEST" ]] || { echo "  (no MANIFEST; a backup from before checksums were recorded)"; return 0; }
  while read -r name sum; do
    if [[ ! -f "$dir/$name" ]]; then
      echo "  missing: $name" >&2; failed=1
    elif [[ "$(sha256sum "$dir/$name" | cut -d' ' -f1)" != "$sum" ]]; then
      echo "  checksum mismatch: $name" >&2; failed=1
    fi
  done < <(sed -n 's/^stored \([^ ]*\) size=[0-9]* sha256=\([0-9a-f]*\)$/\1 \2/p' "$dir/MANIFEST")
  return $failed
}

# The Docker volume behind a compose volume key (models, honeypot_data, ...).
volume_name() {
  docker compose config --format json 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['volumes']['$1']['name'])" 2>/dev/null \
    || echo "honeysentinel_$1"
}

# An image that is always present where a backup or restore runs and has
# tar: the pinned Postgres image. Used for the throwaway containers that
# read and write volumes, so nothing is pulled at backup time.
helper_image() {
  docker compose config --images 2>/dev/null | grep -m1 '^postgres' \
    || { echo "could not determine the Postgres image from the compose file" >&2; return 1; }
}

ROW_TABLES="honeypot_sessions alerts payload_samples indicators_of_compromise audit_logs users honeypot_nodes"

row_counts() {  # row_counts <psql command...>: "table count" per line
  local table query=""
  for table in $ROW_TABLES; do
    query+="${query:+ union all }select '$table', count(*) from $table"
  done
  "$@" -AtF' ' -c "$query"
}
