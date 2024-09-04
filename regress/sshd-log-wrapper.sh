#!/bin/sh
timestamp="`/home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/regress/timestamp`"
logfile="/home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/regress/log/${timestamp}.sshd.$$.log"
rm -f /home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/regress/sshd.log
touch $logfile
test -z "" || chown kk $logfile
ln -f -s ${logfile} /home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/regress/sshd.log
echo "Executing: /home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/sshd $@" log ${logfile} >>/home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/regress/regress.log
echo "Executing: /home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/sshd $@" >>${logfile}
exec /home/kk/workspace/Open-quantum-safe/SSHv9.8.merge/openssh-portable/sshd -E${logfile} "$@"
