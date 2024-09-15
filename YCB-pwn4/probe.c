#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mmap_addr> <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned long addr = strtoll(argv[1], NULL, 16);

    int fd = open(argv[2], O_RDONLY);
    if (fd == -1) {
        perror("open");
        return EXIT_FAILURE;
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return EXIT_FAILURE;
    }

    void *file_memory = mmap((void*)addr, sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE, fd, 0);
    if (file_memory == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);

    // Jump to the mapped memory and execute
    void (*func)() = file_memory;
    func();

    // Clean up
    munmap(file_memory, sb.st_size);

    return EXIT_SUCCESS;
}