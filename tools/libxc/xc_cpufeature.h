/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LIBXC_CPUFEATURE_H
#define __LIBXC_CPUFEATURE_H

/* Intel-defined CPU features, CPUID level 0x00000001 (edx), word 0 */
#define X86_FEATURE_FPU		(0*32+ 0) /* Onboard FPU */
#define X86_FEATURE_VME		(0*32+ 1) /* Virtual Mode Extensions */
#define X86_FEATURE_DE		(0*32+ 2) /* Debugging Extensions */
#define X86_FEATURE_PSE 	(0*32+ 3) /* Page Size Extensions */
#define X86_FEATURE_TSC		(0*32+ 4) /* Time Stamp Counter */
#define X86_FEATURE_MSR		(0*32+ 5) /* Model-Specific Registers, RDMSR, WRMSR */
#define X86_FEATURE_PAE		(0*32+ 6) /* Physical Address Extensions */
#define X86_FEATURE_MCE		(0*32+ 7) /* Machine Check Architecture */
#define X86_FEATURE_CX8		(0*32+ 8) /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC	(0*32+ 9) /* Onboard APIC */
#define X86_FEATURE_SEP		(0*32+11) /* SYSENTER/SYSEXIT */
#define X86_FEATURE_MTRR	(0*32+12) /* Memory Type Range Registers */
#define X86_FEATURE_PGE		(0*32+13) /* Page Global Enable */
#define X86_FEATURE_MCA		(0*32+14) /* Machine Check Architecture */
#define X86_FEATURE_CMOV	(0*32+15) /* CMOV instruction (FCMOVCC and FCOMI too if FPU present) */
#define X86_FEATURE_PAT		(0*32+16) /* Page Attribute Table */
#define X86_FEATURE_PSE36	(0*32+17) /* 36-bit PSEs */
#define X86_FEATURE_PN		(0*32+18) /* Processor serial number */
#define X86_FEATURE_CLFLSH	(0*32+19) /* Supports the CLFLUSH instruction */
#define X86_FEATURE_DS		(0*32+21) /* Debug Store */
#define X86_FEATURE_ACPI	(0*32+22) /* ACPI via MSR */
#define X86_FEATURE_MMX		(0*32+23) /* Multimedia Extensions */
#define X86_FEATURE_FXSR	(0*32+24) /* FXSAVE and FXRSTOR instructions (fast save and restore */
				          /* of FPU context), and CR4.OSFXSR available */
#define X86_FEATURE_XMM		(0*32+25) /* Streaming SIMD Extensions */
#define X86_FEATURE_XMM2	(0*32+26) /* Streaming SIMD Extensions-2 */
#define X86_FEATURE_SELFSNOOP	(0*32+27) /* CPU self snoop */
#define X86_FEATURE_HT		(0*32+28) /* Hyper-Threading */
#define X86_FEATURE_ACC		(0*32+29) /* Automatic clock control */
#define X86_FEATURE_IA64	(0*32+30) /* IA-64 processor */
#define X86_FEATURE_PBE		(0*32+31) /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define X86_FEATURE_SYSCALL	(1*32+11) /* SYSCALL/SYSRET */
#define X86_FEATURE_MP		(1*32+19) /* MP Capable. */
#define X86_FEATURE_NX		(1*32+20) /* Execute Disable */
#define X86_FEATURE_MMXEXT	(1*32+22) /* AMD MMX extensions */
#define X86_FEATURE_FFXSR       (1*32+25) /* FFXSR instruction optimizations */
#define X86_FEATURE_PAGE1GB	(1*32+26) /* 1Gb large page support */
#define X86_FEATURE_RDTSCP	(1*32+27) /* RDTSCP */
#define X86_FEATURE_LM		(1*32+29) /* Long Mode (x86-64) */
#define X86_FEATURE_3DNOWEXT	(1*32+30) /* AMD 3DNow! extensions */
#define X86_FEATURE_3DNOW	(1*32+31) /* 3DNow! */

/* Transmeta-defined CPU features, CPUID level 0x80860001, word 2 */
#define X86_FEATURE_RECOVERY	(2*32+ 0) /* CPU in recovery mode */
#define X86_FEATURE_LONGRUN	(2*32+ 1) /* Longrun power control */
#define X86_FEATURE_LRTI	(2*32+ 3) /* LongRun table interface */

/* Other features, Linux-defined mapping, word 3 */
/* This range is used for feature bits which conflict or are synthesized */
#define X86_FEATURE_CXMMX	(3*32+ 0) /* Cyrix MMX extensions */
#define X86_FEATURE_K6_MTRR	(3*32+ 1) /* AMD K6 nonstandard MTRRs */
#define X86_FEATURE_CYRIX_ARR	(3*32+ 2) /* Cyrix ARRs (= MTRRs) */
#define X86_FEATURE_CENTAUR_MCR	(3*32+ 3) /* Centaur MCRs (= MTRRs) */
/* cpu types for specific tunings: */
#define X86_FEATURE_K8		(3*32+ 4) /* Opteron, Athlon64 */
#define X86_FEATURE_K7		(3*32+ 5) /* Athlon */
#define X86_FEATURE_P3		(3*32+ 6) /* P3 */
#define X86_FEATURE_P4		(3*32+ 7) /* P4 */
#define X86_FEATURE_CONSTANT_TSC (3*32+ 8) /* TSC ticks at a constant rate */

/* Intel-defined CPU features, CPUID level 0x00000001 (ecx), word 4 */
#define X86_FEATURE_XMM3	(4*32+ 0) /* Streaming SIMD Extensions-3 */
#define X86_FEATURE_PCLMULQDQ	(4*32+ 1) /* Carry-less multiplication */
#define X86_FEATURE_DTES64	(4*32+ 2) /* 64-bit Debug Store */
#define X86_FEATURE_MWAIT	(4*32+ 3) /* Monitor/Mwait support */
#define X86_FEATURE_DSCPL	(4*32+ 4) /* CPL Qualified Debug Store */
#define X86_FEATURE_VMXE	(4*32+ 5) /* Virtual Machine Extensions */
#define X86_FEATURE_SMXE	(4*32+ 6) /* Safer Mode Extensions */
#define X86_FEATURE_EST		(4*32+ 7) /* Enhanced SpeedStep */
#define X86_FEATURE_TM2		(4*32+ 8) /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3	(4*32+ 9) /* Supplemental Streaming SIMD Extensions-3 */
#define X86_FEATURE_CID		(4*32+10) /* Context ID */
#define X86_FEATURE_CX16        (4*32+13) /* CMPXCHG16B */
#define X86_FEATURE_XTPR	(4*32+14) /* Send Task Priority Messages */
#define X86_FEATURE_PDCM	(4*32+15) /* Perf/Debug Capability MSR */
#define X86_FEATURE_DCA		(4*32+18) /* Direct Cache Access */
#define X86_FEATURE_SSE4_1	(4*32+19) /* Streaming SIMD Extensions 4.1 */
#define X86_FEATURE_SSE4_2	(4*32+20) /* Streaming SIMD Extensions 4.2 */
#define X86_FEATURE_X2APIC      (4*32+21) /* x2APIC */
#define X86_FEATURE_POPCNT	(4*32+23) /* POPCNT instruction */
#define X86_FEATURE_TSC_DEADLINE (4*32+24) /* "tdt" TSC Deadline Timer */
#define X86_FEATURE_AES		(4*32+25) /* AES acceleration instructions */
#define X86_FEATURE_XSAVE	(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define X86_FEATURE_AVX		(4*32+28) /* Advanced Vector Extensions */
#define X86_FEATURE_F16C	(4*32+29) /* Half-precision convert instruction */
#define X86_FEATURE_HYPERVISOR	(4*32+31) /* Running under some hypervisor */

/* VIA/Cyrix/Centaur-defined CPU features, CPUID level 0xC0000001, word 5 */
#define X86_FEATURE_XSTORE	(5*32+ 2) /* on-CPU RNG present (xstore insn) */
#define X86_FEATURE_XSTORE_EN	(5*32+ 3) /* on-CPU RNG enabled */
#define X86_FEATURE_XCRYPT	(5*32+ 6) /* on-CPU crypto (xcrypt insn) */
#define X86_FEATURE_XCRYPT_EN	(5*32+ 7) /* on-CPU crypto enabled */
#define X86_FEATURE_ACE2	(5*32+ 8) /* Advanced Cryptography Engine v2 */
#define X86_FEATURE_ACE2_EN	(5*32+ 9) /* ACE v2 enabled */
#define X86_FEATURE_PHE		(5*32+ 10) /* PadLock Hash Engine */
#define X86_FEATURE_PHE_EN	(5*32+ 11) /* PHE enabled */
#define X86_FEATURE_PMM		(5*32+ 12) /* PadLock Montgomery Multiplier */
#define X86_FEATURE_PMM_EN	(5*32+ 13) /* PMM enabled */

/* More extended AMD flags: CPUID level 0x80000001, ecx, word 6 */
#define X86_FEATURE_LAHF_LM     (6*32+ 0) /* LAHF/SAHF in long mode */
#define X86_FEATURE_CMP_LEGACY  (6*32+ 1) /* If yes HyperThreading not valid */
#define X86_FEATURE_SVM         (6*32+ 2) /* Secure virtual machine */
#define X86_FEATURE_EXTAPIC     (6*32+ 3) /* Extended APIC space */
#define X86_FEATURE_CR8_LEGACY  (6*32+ 4) /* CR8 in 32-bit mode */
#define X86_FEATURE_ABM         (6*32+ 5) /* Advanced bit manipulation */
#define X86_FEATURE_SSE4A       (6*32+ 6) /* SSE-4A */
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) /* Misaligned SSE mode */
#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) /* 3DNow prefetch instructions */
#define X86_FEATURE_OSVW        (6*32+ 9) /* OS Visible Workaround */
#define X86_FEATURE_IBS         (6*32+10) /* Instruction Based Sampling */
#define X86_FEATURE_XOP         (6*32+11) /* extended AVX instructions */
#define X86_FEATURE_SKINIT      (6*32+12) /* SKINIT/STGI instructions */
#define X86_FEATURE_WDT         (6*32+13) /* Watchdog timer */
#define X86_FEATURE_LWP         (6*32+15) /* Light Weight Profiling */
#define X86_FEATURE_FMA4        (6*32+16) /* 4 operands MAC instructions */
#define X86_FEATURE_NODEID_MSR  (6*32+19) /* NodeId MSR */
#define X86_FEATURE_TBM         (6*32+21) /* trailing bit manipulations */
#define X86_FEATURE_TOPOEXT     (6*32+22) /* topology extensions CPUID leafs */

/* Intel-defined CPU features, CPUID level 0x00000007:0 (ebx), word 9 */
#define X86_FEATURE_FSGSBASE	(7*32+ 0) /* {RD,WR}{FS,GS}BASE instructions */

#endif /* __LIBXC_CPUFEATURE_H */
