#!/bin/sh
set -eu

useradd --create-home --shell /bin/bash labuser
printf '# module-target-root-cron\n7 3 * * * /usr/bin/printf root-cron-proof > /dev/null\n' | crontab -u root -
printf '# module-target-user-cron\n8 3 * * * /usr/bin/printf user-cron-proof > /dev/null\n' | crontab -u labuser -
install -d -m 700 -o labuser -g labuser /home/labuser/.ssh
runuser -u labuser -- ssh-keygen -q -t ed25519 -N '' -f /home/labuser/.ssh/id_ed25519
mkdir -p /run/sshd
/usr/sbin/sshd -t

printf '\n192.0.2.123 firewall-proof.module-target.test\n' >> /etc/hosts
iptables -w 2 -A INPUT -s 192.0.2.123 -m comment --comment module-target-firewall-proof -j ACCEPT

# These are genuine installed configurations. Neither cron nor sshd is started;
# this profile qualifies collection, not scheduled execution or SSH delivery.
exec python3 -m http.server 8080 --bind 0.0.0.0 --directory /opt/health
