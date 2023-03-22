#for sysflow_loadable
obj-m += sysflow.o
# You can't use sysflow_lsm_test.o here, because it will cause
# a cycle. (We have already specify sysflow_lsm_test.o for obj-m)
#sysflow_lsm-objs := sysflow.o sysflow_lsm_main.o 
sysflow-objs := flow_table.o nf_hooker.o lsm_hooker.o sysflow_dp.o

#KBUILD_CFLAGS += -w

all:
	make -C  /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
