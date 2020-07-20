all: shellcode.bin s
.PHONY: all

AS=arm-none-eabi-as
COPY=arm-none-eabi-objcopy
CC=../../gmini-simulator/buildroot-gmini-qemu/output/host/usr/bin/arm-buildroot-linux-uclibcgnueabi-gcc

shellcode.o: shellcode.s
	$(AS) shellcode.s -o shellcode.o

shellcode.bin: shellcode.o
	$(COPY) -O binary shellcode.o shellcode.bin

s: s.c
	$(CC) -Wall -static -s s.c -o s

clean:
	rm -rf shellcode.o shellcode.bin s