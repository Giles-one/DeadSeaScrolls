.PHONY: run clean gdb download.glibc.source

CC := gcc
CFLAGS := -ggdb -w
OUTPUT := house.of.apple

all: $(OUTPUT)
house.of.apple: house.of.apple.c utils.h
	$(CC) -o $@ $(CFLAGS) $<

download.glibc.source:
	apt source libc6 

run: house.of.apple
	./$<

gdb: house.of.apple 
	gdb $^ -nh -d $(wildcard $(CURDIR)/glibc-*/)

clean: 
	rm $(OUTPUT)
