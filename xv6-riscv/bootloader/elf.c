#include "types.h"
#include "param.h"
#include "layout.h"
#include "riscv.h"
#include "defs.h"
#include "buf.h"
#include "elf.h"

#include <stdbool.h>

// struct elfhdr *kernel_elfhdr;
// struct proghdr *kernel_phdr;
uint64 addr;

uint64 find_kernel_load_addr(enum kernel ktype)
{
    /* CSE 536: Get kernel load address from headers */

    if (ktype == NORMAL)
    {
        addr = RAMDISK;
    }
    else if (ktype == RECOVERY)
    {
        addr = RECOVERYDISK;
    }
    struct elfhdr *kernel_elfhdr = (struct elfhdr *)addr;
    uint64 phoff = kernel_elfhdr->phoff;
    uint64 phentsize = kernel_elfhdr->phentsize;
    struct proghdr *text_proghdr = (struct proghdr *)(addr + phoff + phentsize);
    uint64 kernload_start = text_proghdr->vaddr;

    return kernload_start;
}

uint64 find_kernel_size(enum kernel ktype)
{
    /* CSE 536: Get kernel binary size from headers */

    if (ktype == NORMAL)
    {
        addr = RAMDISK;
    }
    else if (ktype == RECOVERY)
    {
        addr = RECOVERYDISK;
    }
    struct elfhdr *kernel_elfhdr = (struct elfhdr *)addr;
    uint64 shentsize = kernel_elfhdr->shentsize;
    uint64 shnum = kernel_elfhdr->shnum;
    uint64 kernel_size = kernel_elfhdr->shoff + shentsize * shnum;

    return kernel_size;
}

uint64 find_kernel_entry_addr(enum kernel ktype)
{
    /* CSE 536: Get kernel entry point from headers */

    if (ktype == NORMAL)
    {
        addr = RAMDISK;
    }
    else if (ktype == RECOVERY)
    {
        addr = RECOVERYDISK;
    }
    struct elfhdr *kernel_elfhdr = (struct elfhdr *)addr;
    uint64 kernel_entry = kernel_elfhdr->entry;
    return kernel_entry;
}
