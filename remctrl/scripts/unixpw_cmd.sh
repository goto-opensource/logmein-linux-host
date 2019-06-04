#!/bin/bash
# x11vnc -unixpw_cmd script.
# Read the first two lines of stdin (user and passwd)
read user
read pass

debug=0
if [ $debug = 1 ]; then
	echo "user: $user" 1>&2
	echo "pass: $pass" 1>&2
	env | egrep -i 'rfb|vnc' 1>&2
fi

if [ "$user" != "$USER" ]; then
	exit 1	# incorrect password
fi

#
# TODO: this is not working at the moment... Reading password from not a terminal is not working.
#

ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
    -o PreferredAuthentications=password,keyboard-interactive \
	-o NumberOfPasswordPrompts=1 localhost "echo OK" || exit 1


