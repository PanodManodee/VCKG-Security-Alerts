#!/bin/sh
# Create the workstation user (with dummy documents), then run sshd in the foreground.
#   PC_USER / PC_PASSWORD   login account,   PC_ADMIN=1   gives it sudo (Admin-PC)
set -eu
USER_NAME="${PC_USER:-user}"
USER_PASS="${PC_PASSWORD:-Passw0rd!}"

if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$USER_NAME"
    echo "$USER_NAME:$USER_PASS" | chpasswd
    [ "${PC_ADMIN:-0}" = "1" ] && usermod -aG sudo "$USER_NAME"
    home="/home/$USER_NAME"
    mkdir -p "$home/Documents"
    echo "Meeting notes (dummy). Next review: Friday." > "$home/Documents/notes.txt"
    echo "db host: 10.10.30.31  user: postgres" > "$home/Documents/connections.txt"   # bait for discovery
    chown -R "$USER_NAME:$USER_NAME" "$home"
fi

mkdir -p /run/sshd
ssh-keygen -A >/dev/null
# No -e: sshd logs to syslog, so logins land in /var/log/auth.log for the Wazuh agent.
exec /usr/sbin/sshd -D
