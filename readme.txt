Tool to run on low power linux machine e.g. raspberry pi or other sbc to wake a larger/more power hungry machine using wake-on-lan.

Dependencies:
libsodium, install with:
debian:
apt install libsodium-dev
fedora:
dnf install libsodium
gentoo:
emerge dev-libs/libsodium

Compile:
mkdir build
cd build
cmake ..
make

Pre setup:
Follow a guide to enable wake-on-LAN (WOL) for your target machine.

Install:

On interwake server:
mkdir /etc/interwake
cp interwake.conf /etc/interwake/
#configure /etc/interwake/interwake.conf with mac address of machine and port for daemon to listen on
#create a keyfile
dd if=/dev/urandom of=/etc/interwake/interwakeKeyfile bs=1 count=512

On interwake client:
copy keyfile from server to ~/.config/interwakeKeyfile
