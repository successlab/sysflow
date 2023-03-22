# Description

This is a simple demo of how to develop a loadable kernel module based on ***simple*** module. 

# Install

Run
```
make
insmod ./sysflow_loadable.ko
lsmod | grep sysflow_loadable
dmesg
```
You should see the logs throgh dmesg


# Develop 

Just include ***<linux/security.h>*** and ***<linux/sysflow.h>***

For more details please see [linux-3.2.0/security/sample/README.md](../../sample/README.md).


