#!/bin/sh
# Create the SMB account from the environment, then run smbd in the foreground.
set -eu
USER_NAME="${SMB_USER:-alice}"
USER_PASS="${SMB_PASSWORD:-Passw0rd!}"

getent group smbusers >/dev/null || groupadd smbusers
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd -M -s /usr/sbin/nologin -G smbusers "$USER_NAME"
    printf '%s\n%s\n' "$USER_PASS" "$USER_PASS" | smbpasswd -s -a "$USER_NAME"
fi
exec smbd --foreground --no-process-group
