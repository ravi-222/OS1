/* These files have been taken from the open-source xv6 Operating System codebase (MIT License).  */

#include "types.h"
#include "param.h"
#include "layout.h"
#include "riscv.h"
#include "defs.h"
#include "buf.h"
#include "measurements.h"
#include <stdbool.h>

void main();
void timerinit();

/* entry.S needs one stack per CPU */
__attribute__((aligned(16))) char bl_stack[STSIZE * NCPU];
uint64 bl_stack_end = (uint64)&bl_stack + (STSIZE * NCPU);

/* Context (SHA-256) for secure boot */
SHA256_CTX sha256_ctx;

/* Structure to collects system information */
struct sys_info
{
  /* Bootloader binary addresses */
  uint64 bl_start;
  uint64 bl_end;
  /* Accessible DRAM addresses (excluding bootloader) */
  uint64 dr_start;
  uint64 dr_end;
  /* Kernel SHA-256 hashes */
  BYTE expected_kernel_measurement[32];
  BYTE observed_kernel_measurement[32];
};
struct sys_info *sys_info_ptr;

extern void _entry(void);
void panic(char *s)
{
  for (;;)
    ;
}

/* CSE 536: Boot into the RECOVERY kernel instead of NORMAL kernel
 * when hash verification fails. */
void setup_recovery_kernel(void)
{
}

/* CSE 536: Function verifies if NORMAL kernel is expected or tampered. */
bool is_secure_boot(void)
{
  bool verification = true;
  /* Read the binary and update the observed measurement
   * (simplified template provided below) */
  sha256_init(&sha256_ctx);

  struct buf b;

  sha256_update(&sha256_ctx, b.data, BSIZE);

  sha256_final(&sha256_ctx, sys_info_ptr->observed_kernel_measurement);

  /* Three more tasks required below:
   *  1. Compare observed measurement with expected hash
   *  2. Setup the recovery kernel if comparison fails
   *  3. Copy expected kernel hash to the system information table */

  if (memcmp(sys_info_ptr->observed_kernel_measurement, sys_info_ptr->expected_kernel_measurement, 32) != 0)
    verification = false;

  if (!verification)
    setup_recovery_kernel();

  return verification;
}

// entry.S jumps here in machine mode on stack0.
void start()
{
  /* CSE 536: Define the system information table's location. */
  sys_info_ptr = (struct sys_info *)0x80080000;

  // keep each CPU's hartid in its tp register, for cpuid().
  int id = r_mhartid();
  w_tp(id);

  // set M Previous Privilege mode to Supervisor, for mret.
  unsigned long x = r_mstatus();
  x &= ~MSTATUS_MPP_MASK;
  x |= MSTATUS_MPP_S;
  w_mstatus(x);

  // disable paging
  w_satp(0);

/* CSE 536: Unless kernelpmp[1-2] booted, allow all memory
 * regions to be accessed in S-mode. */
#if !defined(KERNELPMP1) || !defined(KERNELPMP2)
  w_pmpaddr0(0x3fffffffffffffull);
  w_pmpcfg0(0xf);
#endif

/* CSE 536: With kernelpmp1, isolate upper 10MBs using TOR */
#if defined(KERNELPMP1)
  w_pmpaddr0((0x80000000 + 117 * 1024 * 1024) >> 2);
  w_pmpcfg0(0xF);
#endif

/* CSE 536: With kernelpmp2, isolate 118-120 MB and 122-126 MB using NAPOT */
#if defined(KERNELPMP2)
  w_pmpaddr0((0x80000000 + 118 * 1024 * 1024 - 1) >> 2);
  w_pmpcfg0(0x1f111f110f);
  w_pmpaddr1(((0x80000000 + 118 * 1024 * 1024) >> 2) + ((2 * 1024 * 1024) >> 3) - 1);
  w_pmpaddr2(((0x80000000 + 120 * 1024 * 1024) >> 2) + ((2 * 1024 * 1024) >> 3) - 1);
  w_pmpaddr3(((0x80000000 + 122 * 1024 * 1024) >> 2) + ((4 * 1024 * 1024) >> 3) - 1);
  w_pmpaddr4(((0x80000000 + 126 * 1024 * 1024) >> 2) + ((2 * 1024 * 1024) >> 3) - 1);
#endif

  /* CSE 536: Verify if the kernel is untampered for secure boot */
  /* if (!is_secure_boot())
  { */
  /*Skip loading since we should have booted into a recovery kernel
    in the function is_secure_boot() */
  /*  goto out;
 } */

  /* CSE 536: Load the NORMAL kernel binary (assuming secure boot passed). */
  uint64 kernel_load_addr = find_kernel_load_addr(NORMAL);
  uint64 kernel_binary_size = find_kernel_size(NORMAL);
  uint64 kernel_entry = find_kernel_entry_addr(NORMAL);

  uint64 blockno = (kernel_binary_size - 4096) / 1024;

  struct buf b;
  for (int i = 4; i <= blockno; i++)
  {
    b.blockno = i;
    kernel_copy(NORMAL, &b);
    memmove((void *)kernel_load_addr, (int *)b.data, 1024);
    kernel_load_addr += 1024;
  }

  /* CSE 536: Write the correct kernel entry point */
  w_mepc((uint64)kernel_entry);

  // out:

  /* CSE 536: Provide system information to the kernel. */
  sys_info_ptr->bl_start = 0x80000000;
  sys_info_ptr->bl_end = end;
  sys_info_ptr->dr_start = 0x80000000;
  sys_info_ptr->dr_end = 0x80000000 + 128 * (1024 * 1024);

  /* CSE 536: Send the observed hash value to the kernel (using sys_info_ptr) */

  // delegate all interrupts and exceptions to supervisor mode.
  w_medeleg(0xffff);
  w_mideleg(0xffff);
  w_sie(r_sie() | SIE_SEIE | SIE_STIE | SIE_SSIE);

  // return address fix
  uint64 addr = (uint64)panic;
  asm volatile("mv ra, %0" : : "r"(addr));

  // switch to supervisor mode and jump to main().
  asm volatile("mret");
}
