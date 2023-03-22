#!/bin/bash
sudo make -j 6
sudo make modules install
sudo make install
sudo cp grub.cfg /boot/grub/
