all: exp probe hook.so

CC := gcc
LD := ld

exp: exp.c shellcode.S linker.ld
	$(CC) -w -c shellcode.S -o shellcode.o
	$(CC) -ffreestanding -w -c exp.c -o exp.o
	$(LD) shellcode.o exp.o -o $@ -T linker.ld

exp.bin: exp
	objcopy -O binary -j .text $^ $@

exp.h: exp.bin
	xxd -i $^ > $@

probe: probe.c exp.bin
	$(CC) -ggdb -o $@ $<

hook.so: hook.c exp.h
	$(CC) -ggdb -w -shared -fPIC -o $@ $<

clean:
	rm *.o exp exp.bin exp.h probe hook.so
