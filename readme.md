## Description
Tool to run on low power linux machine e.g. raspberry pi or other sbc to wake a larger/more power hungry machine using wake-on-lan.

## Dependencies

libsodium  
Install with:  
debian:  
`apt install libsodium-dev`  
fedora:  
`dnf install libsodium`  
gentoo:  
`emerge dev-libs/libsodium`  

## Compile

```
mkdir build
cd build
cmake ..
make
```

## Install

`sudo make install`

### On interwake server:

```
mkdir /usr/local/etc/interwake
cp interwake.conf /usr/local/etc/interwake/
#create a keyfile:
dd if=/dev/urandom of=/usr/local/etc/interwake/interwakeKeyfile bs=1 count=512
```
configure /usr/local/etc/interwake/interwake.conf with mac address of machine and port for daemon to listen on  
run with ./interwaked or optionally:  
use interwake.service systemd unit file, can be placed in /usr/local/lib/systemd/system


### On interwake client:

copy keyfile from server to ~/.config/interwakeKeyfile.  
Follow a guide to enable wake-on-LAN (WOL) for your target machine.

## Use
On client: `interwake hostname port`
