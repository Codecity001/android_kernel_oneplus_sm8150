# Baseband-guard (vc-teahouse) in-tree build for 4.14
ccflags-y += -I$(srctree)/security/selinux/include -I$(srctree)/security/selinux
ccflags-y += -I$(objtree)/security/selinux
ccflags-y += -I$(srctree)/block
ccflags-y += -DBBG_VERSION=\"in-tree\" -DBBG_REPO=\"vc-teahouse/Baseband-guard\"

obj-$(CONFIG_BBG)	+= bbg.o
bbg-y := baseband_guard.o blkdev_helper.o