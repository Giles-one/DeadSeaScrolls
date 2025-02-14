```c
(gdb) ptype _IO_2_1_stderr_
type = struct _IO_FILE_plus {
    FILE file;
    const struct _IO_jump_t *vtable;
}
(gdb) ptype /xo struct _IO_FILE_plus
/* offset      |    size */  type = struct _IO_FILE_plus {
/* 0x0000      |  0x00d8 */    FILE file;
/* 0x00d8      |  0x0008 */    const struct _IO_jump_t *vtable;

                               /* total size (bytes):  224 */
                             }
(gdb) ptype /xo FILE
type = struct _IO_FILE {
/* 0x0000      |  0x0004 */    int _flags;
/* XXX  4-byte hole      */
/* 0x0008      |  0x0008 */    char *_IO_read_ptr;
/* 0x0010      |  0x0008 */    char *_IO_read_end;
/* 0x0018      |  0x0008 */    char *_IO_read_base;
/* 0x0020      |  0x0008 */    char *_IO_write_base;
/* 0x0028      |  0x0008 */    char *_IO_write_ptr;
/* 0x0030      |  0x0008 */    char *_IO_write_end;
/* 0x0038      |  0x0008 */    char *_IO_buf_base;
/* 0x0040      |  0x0008 */    char *_IO_buf_end;
/* 0x0048      |  0x0008 */    char *_IO_save_base;
/* 0x0050      |  0x0008 */    char *_IO_backup_base;
/* 0x0058      |  0x0008 */    char *_IO_save_end;
/* 0x0060      |  0x0008 */    struct _IO_marker *_markers;
/* 0x0068      |  0x0008 */    struct _IO_FILE *_chain;
/* 0x0070      |  0x0004 */    int _fileno;
/* 0x0074      |  0x0004 */    int _flags2;
/* 0x0078      |  0x0008 */    __off_t _old_offset;
/* 0x0080      |  0x0002 */    unsigned short _cur_column;
/* 0x0082      |  0x0001 */    signed char _vtable_offset;
/* 0x0083      |  0x0001 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/* 0x0088      |  0x0008 */    _IO_lock_t *_lock;
/* 0x0090      |  0x0008 */    __off64_t _offset;
/* 0x0098      |  0x0008 */    struct _IO_codecvt *_codecvt;
/* 0x00a0      |  0x0008 */    struct _IO_wide_data *_wide_data;
/* 0x00a8      |  0x0008 */    struct _IO_FILE *_freeres_list;
/* 0x00b0      |  0x0008 */    void *_freeres_buf;
/* 0x00b8      |  0x0008 */    size_t __pad5;
/* 0x00c0      |  0x0004 */    int _mode;
/* 0x00c4      |  0x0014 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             }
(gdb) ptype /xo struct _IO_wide_data
/* offset      |    size */  type = struct _IO_wide_data {
/* 0x0000      |  0x0008 */    wchar_t *_IO_read_ptr;
/* 0x0008      |  0x0008 */    wchar_t *_IO_read_end;
/* 0x0010      |  0x0008 */    wchar_t *_IO_read_base;
/* 0x0018      |  0x0008 */    wchar_t *_IO_write_base;
/* 0x0020      |  0x0008 */    wchar_t *_IO_write_ptr;
/* 0x0028      |  0x0008 */    wchar_t *_IO_write_end;
/* 0x0030      |  0x0008 */    wchar_t *_IO_buf_base;
/* 0x0038      |  0x0008 */    wchar_t *_IO_buf_end;
/* 0x0040      |  0x0008 */    wchar_t *_IO_save_base;
/* 0x0048      |  0x0008 */    wchar_t *_IO_backup_base;
/* 0x0050      |  0x0008 */    wchar_t *_IO_save_end;
/* 0x0058      |  0x0008 */    __mbstate_t _IO_state;
/* 0x0060      |  0x0008 */    __mbstate_t _IO_last_state;
/* 0x0068      |  0x0070 */    struct _IO_codecvt {
/* 0x0068      |  0x0038 */        _IO_iconv_t __cd_in;
/* 0x00a0      |  0x0038 */        _IO_iconv_t __cd_out;

                                   /* total size (bytes):  112 */
                               } _codecvt;
/* 0x00d8      |  0x0004 */    wchar_t _shortbuf[1];
/* XXX  4-byte hole      */
/* 0x00e0      |  0x0008 */    const struct _IO_jump_t *_wide_vtable;

                               /* total size (bytes):  232 */
                             }
(gdb) ptype /xo struct _IO_jump_t
/* offset      |    size */  type = struct _IO_jump_t {
/* 0x0000      |  0x0008 */    size_t __dummy;
/* 0x0008      |  0x0008 */    size_t __dummy2;
/* 0x0010      |  0x0008 */    _IO_finish_t __finish;
/* 0x0018      |  0x0008 */    _IO_overflow_t __overflow;
/* 0x0020      |  0x0008 */    _IO_underflow_t __underflow;
/* 0x0028      |  0x0008 */    _IO_underflow_t __uflow;
/* 0x0030      |  0x0008 */    _IO_pbackfail_t __pbackfail;
/* 0x0038      |  0x0008 */    _IO_xsputn_t __xsputn;
/* 0x0040      |  0x0008 */    _IO_xsgetn_t __xsgetn;
/* 0x0048      |  0x0008 */    _IO_seekoff_t __seekoff;
/* 0x0050      |  0x0008 */    _IO_seekpos_t __seekpos;
/* 0x0058      |  0x0008 */    _IO_setbuf_t __setbuf;
/* 0x0060      |  0x0008 */    _IO_sync_t __sync;
/* 0x0068      |  0x0008 */    _IO_doallocate_t __doallocate;
/* 0x0070      |  0x0008 */    _IO_read_t __read;
/* 0x0078      |  0x0008 */    _IO_write_t __write;
/* 0x0080      |  0x0008 */    _IO_seek_t __seek;
/* 0x0088      |  0x0008 */    _IO_close_t __close;
/* 0x0090      |  0x0008 */    _IO_stat_t __stat;
/* 0x0098      |  0x0008 */    _IO_showmanyc_t __showmanyc;
/* 0x00a0      |  0x0008 */    _IO_imbue_t __imbue;

                               /* total size (bytes):  168 */
                             }
```