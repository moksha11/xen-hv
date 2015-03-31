#ifndef MINI_H
#define MINI_H

#include <asm/types.h>
#include <xen/spinlock.h>
#include <xen/list.h>
#include <xen/time.h>
#include <xen/trace.h>

#define QUOTEME_(x)	#x
#define QUOTEME(x)	QUOTEME_(x)
#define USERLAND_END	0x800000000000	// 47 bit

#if CONFIG_PAGING_LEVELS != 4
#error Not-supported.
#endif

#define MAX_PROC	32	//4
#define MAX_CACHE	4	// Also check vr->flag's cachemap (VR_XXX_BASE) and proc2intcache[] and cache2cpumask[]
DECLARE_PER_CPU(s_time_t, cosched_flagtime);
DECLARE_PER_CPU(struct page_dir *, cosched_expected);
DECLARE_PER_CPU(unsigned long, locked_pt);
DECLARE_PER_CPU(unsigned long, found_pt);
DECLARE_PER_CPU(unsigned long, locked_pt_loc);

//#define SUD_DISABLE_SPINLOCK

//#define DEBUG_STAT
#define ENABLE_TRACK_SPINLOCK
#define ENABLE_TRACK_MEMLEAK
#define ENABLE_MYXTRACE
#define ENABLE_RECORD
/*
#define ENABLE_SEPARATE_LIST
*/
#define ENABLE_SEPARATE_ABIT	// use xenheap abit_history
#define ENABLE_SEPARATE_HETERO
/*
#define ENABLE_SEPARATE_VRT	// use separate vregion table from page_info ??
#define ENABLE_SEPARATE_RMAP
*/

#define ONECACHE

// any combination of these should work
//#define ENABLE_INTROSPECT
//#define ENABLE_TIMESTAMP
//#define ENABLE_GUEST_REGION
//#define ENABLE_RANGE		// this requires enable_guest_region
//#define ENABLE_USER_HYPERCALL	// only for 32bit! entry.S and traps.c (in arch/x86/x86_32) are modified.

//#define ENABLE_CACHE_BALANCE
//#define ENABLE_MYPROF
//#define ENABLE_SYSCALL_USCHED	// usched by toggle_guest_mode()
//#define ENABLE_KERNEL_SHADOW
#define ENABLE_LOOP_DETECT
#define ENABLE_PROTECTION_BIT	// this optimizes a bit..
//#define ENABLE_PCPU_STAT
//#define ENABLE_GLOBAL_LIST
//#define VERBOSE_GUEST_TASK

//#define ENABLE_ASYMMETRIC_CACHE
//#define ENABLE_BINPACKING_PRINTX
#define INITIAL_CACHE	initial_cache_alt	// alt,emptiest,first,last,current
#define BALANCE_CORE	core_balance
#define DEST_CACHE	dest_cache_first

// incremental enablings (main)
#define ENABLE_PGD		// pgd and kstack tracking
#define ENABLE_PTMAN		// use ptman for page table access
#define ENABLE_PT_MODIFICATION	// capture all page table modification
#define ENABLE_PT_RECURSIVE	// do recursive pt tracking.
#define ENABLE_VREGIONS
#define ENABLE_MARK_VREGION	// now we're ready for per-cache-pt
#define ENABLE_PER_CACHE_PT	// light-weight cache switch
//#define ENABLE_CHECK_PAGE_TOUCH	// Now we use check_page_touch()
#define ENABLE_RMAP
//#define ENABLE_VREGION_MAPPING	// [open,close]_vregion_cache()
//#define ENABLE_PAGE_TOUCH	// page touch and uschedule
//#define ENABLE_GLOBALIZE1	// globalize code and stack
//#define ENABLE_VR_KERNEL	// kenel vr
//#define ENABLE_VR_USER		// user vr
//#define ENABLE_GLOBALIZE2	//


#define ENABLE_CLOCK
#if 0
#define ENABLE_REGIONING2	// shadow_regioning page table and vtick
#define ENABLE_REGIONING3	// closed entries by default, so causes region switch
#define ENABLE_REGIONING_NOKERNEL	// TODO: remove this
#define ENABLE_REGIONING4	// merge
//#define ENABLE_REGIONING5	// regioning_kstack.. TODO
#define REGIONING_TEMP	// TODO: remove

#define ENABLE_LOCAL_REGION
#endif
#if 0
#define ENABLE_TEARDOWN	// TODO review and rewrite..
#endif

#define ENABLE_BITMAP_BASIC	// basic present bitmap
//#define ENABLE_BITMAP_VRT	// per-cache bitmap.. TODO fix it
#define ENABLE_ABIT
#define ENABLE_HOT_PAGES
//#define ENABLE_HISTOGRAM	// tried to rework 'density' but unsuccessful.. let's not use this
#define ENABLE_HETERO		// migrate pages
#define ENABLE_MULTI_NODE //memory allocation from multiple nodes
#define SLOW_MEMORY_NODE 1
#define FAST_MEMORY_NODE 0
//#define ENABLE_DENSITY
//#define ENABLE_CACHEMAN1
#if 0
//#define ENABLE_BINPACKING	// TODO.. review code
#define ENABLE_MEASURE_UNBALANCE
//#define ENABLE_CORE_BALANCE
#endif
//#define VERBOSE_MEASURE_UNBALANCE

// max depends on the type of 'frames_count' in vregion_t
// If you change the type of 'frames_count', also change type of abit_density to avoid overflow. So they should be of same type
// also modify MAX_MFN_LIST, and MAX_HISTOGRAM
#define MAX_PAGES_IN_VREGION	20000 //65530	//250
//#define MAX_PAGES_IN_VREGION	65530	//250

// conditions
#if !defined(ENABLE_VREGIONS) && defined(ENABLE_GUEST_REGION)
#error guest_region requires vregions
#endif

//--------------------------------------------------------------------------
//#define NO_PGD_ABOVE_4GB	// seems like cr3 is 64bit, so don't need...
//#define DEBUG_MIGRATING_TEST	// this requires CACHE_BALANCE and USCHEDULE
//#define DEBUG_CHECK_COMPARE_PTS
//#define DEBUG_CHECK_OPENCLOSE_MFN

#define VERBOSE_ZERO_PAGE	// zero or cow pages	TODO: embed rw/us bit into vr->flags
#define VERBOSE_USCHED
//#define VERBOSE_USCHED_DETAIL
//#define VERBOSE_UPDATE_CR3
//#define VERBOSE_PAGE_TABLE_INOUT
//#define VERBOSE_TEMP
#define VERBOSE_REGIONING
//#define VERBOSE_REGION_SWITCH
//#define VERBOSE_CLOCK
#define VERBOSE_INFO
#define VERBOSE_PAGE_FAULT


//#define MINI_DEVEL04		// choice..

#ifdef MINI_DEVEL00		// production run
#endif

#ifdef MINI_DEVEL04
#define DEBUG_ASSERT
#define DEBUG_WARN
#endif

#ifdef MINI_DEVEL05
#define DEBUG_ASSERT
#define DEBUG_WARN
#define DEBUG_CHECK_BITMAP
#define DEBUG_CHECK_VREGION
#define DEBUG_CHECK_PT
//#define VERBOSE_USCHED
#define VERBOSE_CACHE_BALANCE
#endif

#ifdef MINI_DEVEL10
#define DEBUG_ASSERT
#define DEBUG_WARN
#define DEBUG_CHECK_BITMAP
#define DEBUG_CHECK_VREGION
#define DEBUG_CHECK_PT

#define VERBOSE_ALLOC_CURRENT_CACHE
#define VERBOSE_UPDATE_CR3
//#define VERBOSE_USCHED
//#define VERBOSE_USCHED_LOOP_DETECTED
//#define VERBOSE_CLOCK
#define VERBOSE_CLOCK_CACHE_ANALYZE
//#define VERBOSE_XEN_SCHEDULE
#endif

#ifdef MINI_DEVEL20
#define DEBUG_ASSERT
#define DEBUG_WARN
#define DEBUG_CHECK_BITMAP
#define DEBUG_CHECK_VREGION
#define DEBUG_CHECK_PT
#define DEBUG_CHECK_PER_CACHE_PT
#define VERBOSE_UPDATE_CR3
#define VERBOSE_BITMAP_PRINT
#define VERBOSE_USCHED_LOOP_DETECTED
#define VERBOSE_CLOCK
#endif

#ifdef MINI_DEVEL30
#define DEBUG_ASSERT
#define DEBUG_WARN
#define DEBUG_CHECK_BITMAP
#define DEBUG_CHECK_VREGION
#define DEBUG_CHECK_PT
#define DEBUG_CHECK_PER_CACHE_PT
//#define VERBOSE_UPDATE_CR3
//#define VERBOSE_PAGE_TABLE_INOUT
#define VERBOSE_USCHED
#define VERBOSE_USCHED_LOOP_DETECTED
//#define VERBOSE_GUEST_TASK
#define VERBOSE_CLOCK_CACHE_ANALYZE
#define VERBOSE_VREGION
#endif

#ifdef MINI_DEVEL40
#define DEBUG_ASSERT
#define DEBUG_WARN
#define DEBUG_CHECK_BITMAP
#define DEBUG_CHECK_VREGION
#define DEBUG_CHECK_PT
#define DEBUG_CHECK_PER_CACHE_PT
#define DEBUG_CHECK_COMPARE_PTS
#define VERBOSE_XEN_SCHEDULE
#define VERBOSE_RMAP
#define VERBOSE_ALLOC_BASIC
#define VERBOSE_PINNING
#define VERBOSE_ALLOC_CURRENT_CACHE
#define VERBOSE_UPDATE_CR3
#define VERBOSE_PAGE_TABLE_INOUT
#define VERBOSE_USCHED
#define VERBOSE_USCHED_LOOP_DETECTED
//#define VERBOSE_CHECK_BITMAP
//#define VERBOSE_BITMAP_CHANGE
//#define VERBOSE_BITMAP_PRINT
//#define VERBOSE_PAGE_TABLE_UPDATE_ENTRY
//#define VERBOSE_PAGE_TABLE_PTWR_EMULATED_UPDATE
#define VERBOSE_CLOCK
#define VERBOSE_GUEST_TASK
#define VERBOSE_CLOCK_CACHE_ANALYZE
#endif

#if 0
/* full development */
#define DEBUG_ASSERT
#define DEBUG_WARN
#define DEBUG_CHECK_BITMAP
#define DEBUG_CHECK_VREGION
#define DEBUG_CHECK_PT
#define DEBUG_CHECK_RMAP
#define DEBUG_CHECK_DUPLICATE_RMAP
#define DEBUG_CHECK_CLEAN_PT
#define DEBUG_CHECK_PER_CACHE_PT
#define DEBUG_CHECK_COMPARE_PTS
#define VERBOSE_XEN_SCHEDULE
#define VERBOSE_RMAP
#define VERBOSE_ALLOC_BASIC
#define VERBOSE_PINNING
#define VERBOSE_ALLOC_CURRENT_CACHE
#define VERBOSE_UPDATE_CR3
#define VERBOSE_PAGE_TABLE_INOUT
#define VERBOSE_PAGE_TABLE_INOUT_LOW
#define VERBOSE_PAGE_TABLE_MARKING
#define VERBOSE_PAGE_TABLE_MARKING_L1E
#define VERBOSE_PAGE_TABLE_L3E_CHANGE_SUCCESS
#define VERBOSE_PAGE_TABLE_L2E_CHANGE_SUCCESS
#define VERBOSE_PAGE_TABLE_L1E_CHANGE_SUCCESS
#define VERBOSE_PAGE_TABLE_L1E_NOT_MANAGED
#define VERBOSE_PAGE_TABLE_UPDATE_ENTRY
#define VERBOSE_PAGE_TABLE_PTWR_EMULATED_UPDATE
#define VERBOSE_USCHED
#define VERBOSE_USCHED_LOOP_DETECTED
#define VERBOSE_CHECK_BITMAP
#define VERBOSE_BITMAP_CHANGE
#define VERBOSE_BITMAP_PRINT
#define VERBOSE_PAGE_FAULT
#define VERBOSE_CLOCK
#define VERBOSE_GUEST_TASK
#define VERBOSE_L1E_CLEAN
#define VERBOSE_CLOCK_CACHE_ANALYZE
#define VERBOSE_CACHE_CONTENTION
#define VERBOSE_NOT_A_PT
#define VERBOSE_VREGION
#define VERBOSE_ZERO_PAGE
#define VERBOSE_CACHE_BALANCE
#define VERBOSE_REGION_SWITCH
#define VERBOSE_REGIONING
#endif


//--------------------------------------------------------
#ifdef DEBUG_ASSERT
#define MYASSERT(p) \
    do { if ( unlikely(!(p)) ) assert_failed(#p); } while (0)
#else
#define MYASSERT(p)	do {} while(0)
#endif

#define MYASSERT_PAGE_IS_VALIDATED(_p)                            \
    MYASSERT(((_p)->u.inuse.type_info & PGT_validated))

#define MYASSERT_PAGE_IS_NOT_VALIDATED(_p)                            \
    MYASSERT(!((_p)->u.inuse.type_info & PGT_validated))

#define MYASSERT_PAGE_IS_TYPE(_p, _t)                            \
    MYASSERT(((_p)->u.inuse.type_info & PGT_type_mask) == (_t)); \
    MYASSERT(((_p)->u.inuse.type_info & PGT_count_mask) != 0)

void heartbeat(void);

#ifdef DEBUG_STAT
#define myprintk(_f, _a...)                              \
	do {						\
		printk("d%dv%d@%d %4d|T[%d+%d]=G:%d+U:%d],%d,%d:%s: " _f, \
		current->domain->domain_id, current->vcpu_id, current->processor, \
		\
		current->vcount[PTOUCH_PAGE_TOUCH], 		\
		\
		pcount[COUNT_PAGE_TOUCH_USER],			\
		pcount[COUNT_PAGE_TOUCH_KERNEL],		\
		pcount[COUNT_GLOBALIZE],			\
		pcount[COUNT_USCHED],				\
		pcount[COUNT_L1E_MARK],				\
		pcount[COUNT_L1E_UNMARK],				\
		__FUNCTION__ , ## _a );			\
	} while (0)
#else
#define myprintk	printk
#endif
/*


		current->count[PTOUCH_PAGE_FAULT], 		\
		current->count[PTOUCH_CPU_PICK], 		\
		current->count[PTOUCH_LOAD_BALANCE], 		\
		pcount[COUNT_CHECK_VREGION],				\
		pcount[COUNT_CHECK_BITMAP],				\
		pcount[COUNT_SYSCALL],	\
		pcount[COUNT_SYSRET],	\


*/

//		current->loop_detected_count, 		

void myprint_xenheap(void);

#define mypanic(_str)		\
do {				\
	int i=0;		\
	myprintk("Mypanic: '%s' failed, line %d, file %s\n", _str , __LINE__, __FILE__);	\
	myprint_xenheap();								\
	for(i=0;i<1000000;i++) ;		\
	BUG();			\
} while(0)

#if 0
#ifdef ENABLE_TRACK_MEMLEAK
	memleak_report();
#endif			
#ifdef ENABLE_TRACK_SPINLOCK
	spinlock_report();
#endif			
#endif
//	show_execution_state(guest_cpu_user_regs());
//	panic(_str);




//#define L1E_OPEN_OVERLAPPED			0UL
#define L1E_CLOSED				1UL
#define L1E_NOT_PRESENT				2UL
//#define L1E_CLOSED_OVERLAPPED			3UL
#define L1E_OPEN				4UL
#define L1E_MAX					5UL

#define PTOUCH_PROPAGATE_GUEST	0
#define PTOUCH_PAGE_FAULT	1
#define PTOUCH_PAGE_TOUCH	2
//#define				3	// empty
#define PTOUCH_LOAD_BALANCE	4
#define PTOUCH_MAX		5

#ifdef ENABLE_ABIT
DECLARE_PER_CPU(unsigned long [BITS_TO_LONGS(L4_PAGETABLE_ENTRIES)], abits);
#endif

struct vregion_t;
struct page_dir;

//#define CPU_PER_CACHE	2	// TODO

#define cachemap_mask		( ((1UL<<VR_CACHEMAP_BASE)-1) ^ ((1UL<<(VR_CACHEMAP_BASE+MAX_CACHE))-1) )
#define cachemap_bitmap(X)	( (X)->flags & cachemap_mask )
#define cachemap_clear(X)	( (X)->flags & ~cachemap_mask )
#define cachemap_count(X)	bitcount(cachemap_bitmap(X))

#define cache_in_mask		( ((1UL<<VR_CACHE_IN_BASE)-1) ^ ((1UL<<(VR_CACHE_IN_BASE+MAX_CACHE))-1) )
#define cache_in_bitmap(X)	( (X)->flags & cache_in_mask )
#define cache_in_clear(X)	( (X)->flags & ~cache_in_mask )
#define cache_in_count(X)	bitcount(cache_in_bitmap(X))

#ifdef ENABLE_CACHEMAN1
struct cache_t {
//	int size;	// static size in KB. fixed.
	spinlock_t lock;
	struct list_head vregions_list;
	int frames_count;
	int vregions_count;
#if 0 // old code
	atomic_t vcpu_count;	// num of vcpu in this cache. ENABLE_MEASURE_UNBALANCE is required
#ifdef ENABLE_DENSITY
	unsigned int abit_density[32];	// prot'ed by lock
#endif
#endif
};

struct cman {
	struct vregion_t *vr;
	struct list_head list[MAX_CACHE];
};

extern struct cache_t cacheman[MAX_CACHE];
void init_cacheman(void);
void region_touch(struct vregion_t *vr, int c, s_time_t now);
void print_cache(int verbose);
void cache_out_all(struct vregion_t *vr);
void shrink_cacheman(int c, s_time_t now);
void check_cacheman_after_cleanup(void);
#define test_cachein(X, Y)	(test_bit(VR_CACHE_IN_BASE+(Y), &(X)->flags))
#endif

#define cache_now	(proc2intcache[smp_processor_id()])
#define cachemap_is_global(X)	(0 == cachemap_bitmap(X))

#ifdef ENABLE_BITMAP_VRT_OLD
#ifdef DEBUG_CHECK_PT
#define myspin_lock_pt(X, Y)	\
	do {			\
		myspin_lock(&((X)->lock), (Y));	\
		if ((X)->init)			\
			check_pt(X, Y);		\
	} while(0);
#define spin_unlock_pt(X, Y)	\
	do {			\
		if ((X)->init)			\
			check_pt(X, -(Y));	\
		spin_unlock(&((X)->lock));	\
	} while(0);
#else
#define myspin_lock_pt(X, Y)	\
	do {			\
		myspin_lock(&((X)->lock), (Y));	\
	} while(0);
#define spin_unlock_pt(X, Y)	\
	do {			\
		spin_unlock(&((X)->lock));	\
	} while(0);
#endif
#else
#define myspin_lock_pt(X, Y)	(0);
#define spin_unlock_pt(X, Y)	(0);
#endif

extern int clock_period_ms;
extern char *machine_name;
extern int max_proc;
extern int max_cache;
extern int proc2intcache[MAX_PROC];
extern cpumask_t cache2cpumask[MAX_CACHE];

struct page_table;

#define MAX_RMAP_ENTRIES_DEFAULT	2
#define MAX_RMAP_ENTRIES_IN_SET		32
struct rmap_set {
	struct list_head list;
	unsigned char entry_count;	// used by split_vregion()/merge_vregion()
	unsigned char flag_count;	// used by split_vregion()/merge_vregion()
	unsigned short int size;	// size of array
	unsigned long rmaps[0];
};

#define RMAPS_USER	0
#define RMAPS_KERNEL	1
#define RMAPS_MAX	2

#ifdef ENABLE_RMAP
struct rmaps_builtin {
	struct list_head rmaps_list;	// protected by lock
	unsigned int rmap_count;	// TODO: move this out to frame_t to save space
	// following two field should be contiguous.
	// don't use second padding field directly.
	struct rmap_set default_rmaps;
	unsigned long default_padding_dont_use[MAX_RMAP_ENTRIES_DEFAULT];
};
#endif

struct frame_t {
#ifndef ENABLE_SEPARATE_VRT
	struct vregion_t *vr;
#endif
#ifdef ENABLE_ABIT
#ifndef ENABLE_SEPARATE_ABIT
	unsigned int abit_history;	//[MAX_CACH];
	unsigned int time;	//[MAX_CACH];
#endif
#endif
#ifdef ENABLE_HETERO
#ifndef ENABLE_SEPARATE_HETERO
	unsigned int hetero_mfn;
#endif
#endif
#ifdef ENABLE_VREGIONS
#ifndef ENABLE_SEPARATE_LIST
	int next;
	int prev;
#endif
#endif
#ifdef ENABLE_RMAP
#ifndef ENABLE_SEPARATE_RMAP
	struct rmaps_builtin rmaps[RMAPS_MAX];
#endif
#endif
};

struct heap_frame_t {
#ifdef ENABLE_SEPARATE_VRT
	struct vregion_t *vr;
#endif
#ifdef ENABLE_ABIT
#ifdef ENABLE_SEPARATE_ABIT
	unsigned int abit_history;	//[MAX_CACHE];
	unsigned int time;	//[MAX_CACHE];
#endif
#endif
#ifdef ENABLE_HETERO
#ifdef ENABLE_SEPARATE_HETERO
	unsigned int hetero_mfn;
#endif
#endif
#ifdef ENABLE_VREGIONS
#ifdef ENABLE_SEPARATE_LIST
	int next;
	int prev;
#endif
#endif
#ifdef ENABLE_RMAP
#ifdef ENABLE_SEPARATE_RMAP
	struct rmaps_builtin rmaps[RMAPS_MAX];
#endif
#endif
};

extern struct heap_frame_t *mytable;

// protected by vrt_lock.
#ifdef ENABLE_SEPARATE_VRT
#define FTABLE_VR(MFN)		(mytable[MFN].vr)
#else
#define FTABLE_VR(MFN)		(frame_table[MFN].frame.vr)
#endif
#ifdef ENABLE_SEPARATE_ABIT
#define FTABLE_ABIT(MFN)		(mytable[MFN].abit_history)
#define FTABLE_TIME(MFN)		(mytable[MFN].time)
#else
#define FTABLE_ABIT(MFN)		(frame_table[MFN].frame.abit_history)
#define FTABLE_TIME(MFN)		(frame_table[MFN].frame.time)
#endif
#ifdef ENABLE_SEPARATE_HETERO
#define FTABLE_HETERO(MFN)		(mytable[MFN].hetero_mfn)
#else
#define FTABLE_HETERO(MFN)		(frame_table[MFN].frame.hetero_mfn)
#endif

// protected by vr->lock
#ifdef ENABLE_SEPARATE_LIST
#define FTABLE_NEXT(MFN)	(mytable[MFN].next)
#define FTABLE_PREV(MFN)	(mytable[MFN].prev)
#else
#define FTABLE_NEXT(MFN)	(frame_table[MFN].frame.next)
#define FTABLE_PREV(MFN)	(frame_table[MFN].frame.prev)
#endif

#ifdef ENABLE_SEPARATE_RMAP
#define FTABLE_RMAPS(MFN, NUM)	(mytable[MFN].rmaps[NUM])
#else
#define FTABLE_RMAPS(MFN, NUM)	(frame_table[MFN].frame.rmaps[NUM])
#endif

inline struct page_table *rme_pt(unsigned long ptr);
inline int rme_pti(unsigned long ptr);
inline void rme_set(unsigned long *ptr, struct page_table *pt, int pti);
inline void rme_set_flag(unsigned long *ptr, int f);

unsigned long *find_rmap(struct vregion_t *vr, struct page_table *pt, int ptindex, unsigned long mfn);
//void add_rmap(struct vregion_t *vr, struct page_table *pt, int ptindex, unsigned long mfn);
void add_rmap(struct vregion_t *vr, struct page_table *pt, int ptindex, unsigned long mfn, int rmapi);
int del_rmap(struct page_table *pt, int ptindex, unsigned long mfn, int rmapi);
int total_rmap(void);
int check_pt_rmap_shared(struct page_table *pt);
int split_vregion_common(struct vregion_t *vr, struct vregion_t *newvr, int choice);

// from pgd.c
unsigned long change_cr3(unsigned long old_base_mfn);

struct page_dir *find_or_add_pgd(unsigned long mfn);

#define VR_CACHEMAP_BASE	(0)	// [0,0+MAX_CACHE)
#define VR_CACHE_IN_BASE	(4)	// [4,4+MAX_CACHE)

#define VR_ATTR_START		(16)	// these will be cleared in del_vregion() when it dies
#define VR_FIXED_MAP		(16)
#define VR_POOL			(17)
#define VR_USER			(18)
#define VR_KERNEL		(19)
#define VR_XEN			(20)
#define VR_NO_REGIONING		(21)	// don't participate in regioning. open entry in regioning_shadow
#define VR_REGULAR		(22)	// do regioning
#define VR_SHRINK_NORMAP	(23)
//#define VR_SEQUENTIAL		(24)

#define VRPRINT_RMAP	(1UL<<31)
#define VRPRINT_DENSITY	(1UL<<30)
//#define ENABLE_ADD_RMAP_OPTIMIZATION	// TODO
#ifdef ENABLE_ADD_RMAP_OPTIMIZATION
	struct rmap_set *free_rmaps;
	int free_rmapi;			// free rmap index
#endif

// TODO: do not call new_vregion_common() directly.. e.g. newshared
// TODO make sure this ordering...
// drop your reference, then decrease refcnt
// increase refcnt, then copy your reference
#if 1
#define VR_REFCNT_GLOBAL	0	// global. see vrt_init()
#define VR_REFCNT_SEED		0	// global. see vrt_init()
#define VR_REFCNT_VRT		0	// global. see vrt_set()
#define VR_REFCNT_GUEST		0	// global. see range.c
#define VR_REFCNT_REGIONING	0	// global. see regioning.c
#define VR_REFCNT_VRT_TEMP	0	// local. return value of vrt_set()
#define VR_REFCNT_RMAP		0	// local. see del_rmap()
#define VR_REFCNT_VRT_FILL_SLOT	0	// local. see vrt_fill_slot()
#define VR_REFCNT_RANGE_TEMP	0	// local. new_vregion()->split_vregion_newrange()->construct_range_vr()
#define VR_REFCNT_SPLIT_VR_NEWRANGE	0	// local. see split_vregion_newrange
//#define VR_REFCNT_MERGE_VREGION		4	// local. see merge_vregion()
#define VR_REFCNT_NEWSHARED	0	// local. see split_vregion_newshared()
#define VR_REFCNT_PAGE_TOUCH_TEMP	0	// local. see page_touch
#define MAX_VR_REFCNT	1
#else
// starting from new_vregion()
#define VR_REFCNT_GLOBAL	3	// global. see vrt_init()
#define VR_REFCNT_SEED		1	// global. see vrt_init()
#define VR_REFCNT_VRT		0	// global. see vrt_set()
#define VR_REFCNT_GUEST		2	// global. see range.c
#define VR_REFCNT_REGIONING	6	// global. see regioning.c
#define VR_REFCNT_VRT_TEMP	2	// local. return value of vrt_set()
#define VR_REFCNT_RMAP		4	// local. see del_rmap(), l1e_mark()
#define VR_REFCNT_VRT_FILL_SLOT	2	// local. see vrt_fill_slot()
#define VR_REFCNT_RANGE_TEMP	5	// local. new_vregion()->split_vregion_newrange()->construct_range_vr()
#define VR_REFCNT_SPLIT_VR_NEWRANGE	3	// local. see split_vregion_newrange
//#define VR_REFCNT_MERGE_VREGION		4	// local. see merge_vregion()
#define VR_REFCNT_NEWSHARED	5	// local. see split_vregion_newshared()
#define VR_REFCNT_PAGE_TOUCH_TEMP	1	// local. see page_touch
#define MAX_VR_REFCNT	7
#endif
// we grep vr's lock before cacheman's
// when you add more fields, also check new_vregion_common()
struct vregion_t {
	atomic_t vr_refcnt[MAX_VR_REFCNT];	// protected by vrt_lock (with vrt table)
	union {
		struct list_head vr_list;	// vregions_[shared,free,private], prot'ed by each list's lock
		struct {
			struct cman *cman;
			void *empty;
		} inuse;
	} u;
#ifdef ENABLE_GLOBAL_LIST
	struct list_head global_list;	// for debugging
#endif
	spinlock_t lock;
	unsigned int frame_count;		// short int was fine, but get_seed() may want large-sized seed region
#if 1 //def ENABLE_RMAP
	unsigned int rmap_count[RMAPS_MAX];	// short int was fine, but with kernel-shadow, sometimes overflow found,so use int.. I think maybe zero-page would have greatest # of rmaps..
#endif
	unsigned int flags;	// protected by test_and_*_bit()
	int head;		// mfn-chain head.
#ifdef ENABLE_HISTOGRAM
	unsigned short abit_histogram[MAX_CACHE][32];
#endif
#ifdef ENABLE_REGIONING3
	s_time_t tpoint;	// time point. entry/exit region time.. 0 if seed region, nonzero when it becomes regular
	s_time_t access;
#endif
#if 0
	unsigned long range;	// in case of sequentual region
#endif
};

extern struct vregion_t *global;

extern atomic_t abit_density_shared[MAX_CACHE][32];

#define MFN_LOCKS_SHIFT	9
#define MFN_LOCKS_MAX	(1UL<<MFN_LOCKS_SHIFT)	// 512
#define SYNC_LOCK(mfn)	(sync_lock[(mfn)&(MFN_LOCKS_MAX-1)])
extern spinlock_t sync_lock[MFN_LOCKS_MAX];

extern spinlock_t vregions_seed_lock;
extern spinlock_t vregions_free_lock;
extern struct list_head vregions_seed;	// not really seed. it has every vr in system. TODO: remove this. should be reference-counted..
extern struct list_head vregions_free;
extern int vregions_seed_count;
extern int vregions_free_count;
extern int vregions_xmalloc_count;
void close_vregion_cache(struct vregion_t *vr, int c);
void open_vregion_cache(struct vregion_t *vr, int c);
void open_vregion_cache_split(struct vregion_t *vr, int c);
void move_vregion_cache(struct vregion_t *vr, int c1, int c2);
#ifdef ENABLE_RMAP
inline void vr_sub_rmap_count(struct vregion_t *vr, int d, int rmapi);
inline void vr_add_rmap_count(struct vregion_t *vr, int d, int rmapi);
inline void vr_dec_rmap_count(struct vregion_t *vr, int rmapi, struct rmaps_builtin *r);
inline void vr_inc_rmap_count(struct vregion_t *vr, int rmapi, struct rmaps_builtin *r);
#endif
inline void vr_dec_frame_count(struct vregion_t *vr);
inline void vr_inc_frame_count(struct vregion_t *vr);
inline void vr_get(struct vregion_t *vr, int loc);
inline void vr_put(struct vregion_t *vr, int loc, int hint);

#ifdef ENABLE_HISTOGRAM
inline void vr_inc_density(struct vregion_t *vr, int i, int cache);
inline void vr_dec_density(struct vregion_t *vr, int i, int cache);
inline void vr_move_density(struct vregion_t *vr, int from, int to, int cache);
inline void vr_reset_density(struct vregion_t *vr, int i, int cache);
/*
#define ACTIVE_FRAMES_VR(X, Y)	(\
	(X)->abit_density[Y][31]+	\
	(X)->abit_density[Y][30]+	\
	(X)->abit_density[Y][29]+	\
	(X)->abit_density[Y][28]+	\
	(X)->abit_density[Y][27]+	\
	(X)->abit_density[Y][26]+	\
	(X)->abit_density[Y][25]/2 + (X)->abit_density[Y][25]/4+	\
	(X)->abit_density[Y][24]/2 + (X)->abit_density[Y][24]/4+	\
	(X)->abit_density[Y][23]/2 + (X)->abit_density[Y][23]/4+	\
	(X)->abit_density[Y][22]/2 + (X)->abit_density[Y][22]/4+	\
	(X)->abit_density[Y][21]/2 + (X)->abit_density[Y][21]/4+	\
	(X)->abit_density[Y][20]/2 + (X)->abit_density[Y][20]/4+	\
	(X)->abit_density[Y][19]/2+	\
	(X)->abit_density[Y][18]/2+	\
	(X)->abit_density[Y][17]/2+	\
	(X)->abit_density[Y][16]/2+	\
	(X)->abit_density[Y][15]/2+	\
	(X)->abit_density[Y][14]/2+	\
	(X)->abit_density[Y][13]/4+	\
	(X)->abit_density[Y][12]/4+	\
	(X)->abit_density[Y][11]/4+	\
	(X)->abit_density[Y][10]/4+	\
	(X)->abit_density[Y][9]/4+	\
	(X)->abit_density[Y][8]/4)

#define ACTIVE_FRAMES_CACHE(X)	(\
	cacheman[X].abit_density[31]+	\
	cacheman[X].abit_density[30]+	\
	cacheman[X].abit_density[29]+	\
	cacheman[X].abit_density[28]+	\
	cacheman[X].abit_density[27]+	\
	cacheman[X].abit_density[26]+	\
	cacheman[X].abit_density[25]/2 + cacheman[X].abit_density[25]/4 + 	\
	cacheman[X].abit_density[24]/2 + cacheman[X].abit_density[24]/4 + 	\
	cacheman[X].abit_density[23]/2 + cacheman[X].abit_density[23]/4 + 	\
	cacheman[X].abit_density[22]/2 + cacheman[X].abit_density[22]/4 + 	\
	cacheman[X].abit_density[21]/2 + cacheman[X].abit_density[21]/4 + 	\
	cacheman[X].abit_density[20]/2 + cacheman[X].abit_density[20]/4 + 	\
	cacheman[X].abit_density[19]/2+	\
	cacheman[X].abit_density[18]/2+	\
	cacheman[X].abit_density[17]/2+	\
	cacheman[X].abit_density[16]/2+	\
	cacheman[X].abit_density[15]/2+	\
	cacheman[X].abit_density[14]/2+	\
	cacheman[X].abit_density[13]/4+	\
	cacheman[X].abit_density[12]/4+	\
	cacheman[X].abit_density[11]/4+	\
	cacheman[X].abit_density[10]/4+	\
	cacheman[X].abit_density[9]/4+	\
	cacheman[X].abit_density[8]/4)
#define ACTIVE_FRAMES_PGD(X, Y)	(\
	atomic_read(&(X)->abit_density[Y][31])+	\
	atomic_read(&(X)->abit_density[Y][30])+	\
	atomic_read(&(X)->abit_density[Y][29])+	\
	atomic_read(&(X)->abit_density[Y][28])+	\
	atomic_read(&(X)->abit_density[Y][27])+	\
	atomic_read(&(X)->abit_density[Y][26])+	\
	atomic_read(&(X)->abit_density[Y][25])/2 + atomic_read(&(X)->abit_density[Y][25])/4+	\
	atomic_read(&(X)->abit_density[Y][24])/2 + atomic_read(&(X)->abit_density[Y][24])/4+	\
	atomic_read(&(X)->abit_density[Y][23])/2 + atomic_read(&(X)->abit_density[Y][23])/4+	\
	atomic_read(&(X)->abit_density[Y][22])/2 + atomic_read(&(X)->abit_density[Y][22])/4+	\
	atomic_read(&(X)->abit_density[Y][21])/2 + atomic_read(&(X)->abit_density[Y][21])/4+	\
	atomic_read(&(X)->abit_density[Y][20])/2 + atomic_read(&(X)->abit_density[Y][20])/4+	\
	atomic_read(&(X)->abit_density[Y][19])/2+	\
	atomic_read(&(X)->abit_density[Y][18])/2+	\
	atomic_read(&(X)->abit_density[Y][17])/2+	\
	atomic_read(&(X)->abit_density[Y][16])/2+	\
	atomic_read(&(X)->abit_density[Y][15])/2+	\
	atomic_read(&(X)->abit_density[Y][14])/2+	\
	atomic_read(&(X)->abit_density[Y][13])/4+	\
	atomic_read(&(X)->abit_density[Y][12])/4+	\
	atomic_read(&(X)->abit_density[Y][11])/4+	\
	atomic_read(&(X)->abit_density[Y][10])/4+	\
	atomic_read(&(X)->abit_density[Y][9])/4+	\
	atomic_read(&(X)->abit_density[Y][8])/4)
#define ACTIVE_FRAMES_SHARED(X)	(\
	atomic_read(&abit_density_shared[X][31])+	\
	atomic_read(&abit_density_shared[X][30])+	\
	atomic_read(&abit_density_shared[X][29])+	\
	atomic_read(&abit_density_shared[X][28])+	\
	atomic_read(&abit_density_shared[X][27])+	\
	atomic_read(&abit_density_shared[X][26])+	\
	atomic_read(&abit_density_shared[X][25])/2 + atomic_read(&abit_density_shared[X][25])/4+	\
	atomic_read(&abit_density_shared[X][24])/2 + atomic_read(&abit_density_shared[X][24])/4+	\
	atomic_read(&abit_density_shared[X][23])/2 + atomic_read(&abit_density_shared[X][23])/4+	\
	atomic_read(&abit_density_shared[X][22])/2 + atomic_read(&abit_density_shared[X][22])/4+	\
	atomic_read(&abit_density_shared[X][21])/2 + atomic_read(&abit_density_shared[X][21])/4+	\
	atomic_read(&abit_density_shared[X][20])/2 + atomic_read(&abit_density_shared[X][20])/4+	\
	atomic_read(&abit_density_shared[X][19])/2+	\
	atomic_read(&abit_density_shared[X][18])/2+	\
	atomic_read(&abit_density_shared[X][17])/2+	\
	atomic_read(&abit_density_shared[X][16])/2+	\
	atomic_read(&abit_density_shared[X][15])/2+	\
	atomic_read(&abit_density_shared[X][14])/2+	\
	atomic_read(&abit_density_shared[X][13])/4+	\
	atomic_read(&abit_density_shared[X][12])/4+	\
	atomic_read(&abit_density_shared[X][11])/4+	\
	atomic_read(&abit_density_shared[X][10])/4+	\
	atomic_read(&abit_density_shared[X][9])/4+	\
	atomic_read(&abit_density_shared[X][8])/4)
*/
#else
// TODO
#define ACTIVE_FRAMES_VR(X, Y)	(0)
#define ACTIVE_FRAMES_CACHE(X)	(0)
#define ACTIVE_FRAMES_PGD(X, Y)	(0)
#define ACTIVE_FRAMES_SHARED(X)	(0)
#endif

#define MAX_VREGION_1MB_POOL	70
extern struct vregion_t *vregion_1mb_pool[MAX_VREGION_1MB_POOL];
extern int vregion_1mb_pool_count;
extern int num_vregions_per_1mb;
inline struct vregion_t *_vrt_get(unsigned mfn, int loc);
inline struct vregion_t *vrt_get(unsigned long mfn, int loc, int sync_locked);
struct vregion_t *vrt_set(unsigned long mfn, struct vregion_t *vr, int flags);
void vrt_init(void);
void vrt_fill_slot(unsigned long mfn, struct page_table *pt, int ptindex);
#define VRT_SET_LOCK_SYNC	0x1
#define VRT_SET_MAYBE_SAME	0x2
#define VRT_SET_SKIP_UNLOCK_VR2	0x4
#define VRT_SET_INIT		0x8
#define VRT_SET_WAS_NULL	0x10
#define VRT_SET_RETURN_OLD	0x20

#ifdef ENABLE_SYSCALL_USCHED
extern int syscall_usched;
#endif

#define COUNT_PAGE_TOUCH_USER	0
#define COUNT_PAGE_TOUCH_KERNEL	1
//#define COUNT_RMAP_DEBUG	2
#define COUNT_L1E_MARK		3
#define COUNT_L1E_UNMARK	4
#define COUNT_USCHED		5
#define COUNT_CHECK_VREGION	6
#define COUNT_CHECK_BITMAP	7
#define COUNT_GLOBALIZE		8
#define COUNT_SYSCALL		9	// TODO make it persistent?
#define COUNT_SYSRET		10	// TODO: make it persistent?
#define COUNT_TOGGLE_MODE	11
#define COUNT_IRET		12
#define COUNT_GUEST_API		13
#define COUNT_CLEAR_ABIT	14
#define COUNT_MAX		16
// TODO: use atomic
extern int pcount[COUNT_MAX];
extern int usched_print;

#define PGD_DYING	0
#define PGD_MIGRATING	1
#define PGD_KERNEL	8

#ifdef ENABLE_GUEST_REGION
#define MAX_RD	512
struct region_descriptor {
	struct vregion_t *vr;
	char name[9];
	int add_count;
	int del_count;
	int range;
};

void init_grt(struct domain *d);
void destroy_grt(struct domain *d);
void print_grt(void);
int add_guest_region(unsigned long intname, int range);
void del_guest_region(int i, int verbose, struct domain *d);
void add_page_guest_region(unsigned long mfn, unsigned long order, unsigned long rd);
void del_page_guest_region(unsigned long mfn, unsigned long order, unsigned long rd);
#endif

#ifdef ENABLE_RANGE
#define MAX_RANGES	4
struct range_t {
	long vfn;
	long count;
	int rd;
};
int add_range(struct page_dir *pgd, long vfn, long count, int rd);
int del_range(struct page_dir *pgd, long vfn, long count);
void del_all_ranges(struct page_dir *pgd);
struct vregion_t *check_range(struct page_dir *pgd,long vfn);
void construct_range_vr(long vfn, long count, struct vregion_t *newvr, int rd);
#endif

#ifdef ENABLE_GLOBALIZE2
#define SHIFT_USCHED_INFO	2
#define MAX_USCHED_INFO		(1UL<<SHIFT_USCHED_INFO)
#define MASK_USCHED_INFO	(MAX_USCHED_INFO-1)
// TODO: remove unnecessary info
struct usched_info {
	unsigned long eip;
	unsigned long addr;
	int from;
	struct vregion_t *vr;
	unsigned int vr_flags;
	unsigned long mfn;
	s_time_t time;
};
void init_ui(struct usched_info *ui);
#endif

struct page_dir {
	struct domain *domain;
	struct page_table *pt;
	unsigned long mfn_user;	// could be 0 because not-detected yet, or no-user-space
	struct list_head list;	// belongs to pgd_list

	atomic_t refcnt;	// # of refs (including v->current_pgd)
	spinlock_t lock;	// protect pt_list, pt_count
	unsigned long flag;	// flag
#if 1	// PGD_STAT
	int mark_count;	// TODO
	int openbit_count[MAX_CACHE];	// openbit_count for each cache
#endif
#ifdef ENABLE_REGIONING2
//	spinlock_t rlock;	// TODO protect entry/exit regioning phase.
	struct vregion_t *current_region;
	int regioning_cpu;
#ifdef ENABLE_REGIONING5
	void *regioning_kstack;
#endif
	int regioning_tick;
	int region_switch_count;
	int sequential_count;
	int merge_count;
	int region_prev_user_page_touch;
	int region_prev_kernel_page_touch;
	s_time_t region_prev_time;
	s_time_t regioning_adjust, regioning_adjust_prev;
	int regioning_pause_reason;
	int regioning_pause_count;
	int regioning_usched_count;
	int newregular_during_normalexec_count;
	int regioning_count;
	struct region_t *regioning_prev_region;
#endif
#ifdef VERBOSE_BITMAP_PRINT
	int opening_count;
#endif
#ifdef ENABLE_DENSITY
	atomic_t abit_density[MAX_CACHE][32];	// this covers only private vrs
#endif
#ifdef ENABLE_CLOCK
	s_time_t clock_residue;
	s_time_t clock_prev_now;
	short int clock_cr3_changes;
	short int clock_timer;
	short int clock_schedule;
	int vtick_count;	// use atomic ?
#endif
#ifdef ENABLE_ABIT
	int clear_abit_count;
#endif
#ifdef ENABLE_RANGE
	struct range_t ranges[MAX_RANGES];
#endif
};


extern spinlock_t temp_lock;
// from ptman.c
struct page_dir *get_pgd(struct page_table *pt);
struct page_table *ptman_find(unsigned long mfn);
struct page_table *find_pt_mfn(unsigned long mfn);
void lock_pt(unsigned long mfn, int level, int loc);
void unlock_pt(int forcibly);


#define L4_GUEST_START	272
#define L4_GUEST_END	385	//511	// TODO
#define L4_GUEST_KERNEL(x)	((x)>=L4_GUEST_START && (x)< L4_GUEST_END)

unsigned long get_va(struct page_table *pt, unsigned int ptindex);

struct vregion_t *get_seed_user(void);
struct vregion_t *get_seed_kernel(void);
struct vregion_t *get_seed_xen(void);

#define ATTR_DATA	1
#define ATTR_CODE	2
#define ATTR_STACK	3

#if 1
void close_bitmap(struct page_table *pt, int ptindex, int dest_cache);
void open_bitmap(struct page_table *pt, int ptindex, int dest_cache);
int test_bitmap(struct page_table *pt, int ptindex, int dest_cache);
void check_bitmap(struct page_dir *pgd);
void print_bitmap(struct page_dir *pgd);

struct l1e_struct {
	unsigned long bitmap[MAX_CACHE+1][BITS_TO_LONGS(L4_PAGETABLE_ENTRIES)];	// 0:present bitmap, 1:cache0, 2:cache1, ... (512 bits)
};
#endif

struct page_table {
	unsigned long mfn;
	int user_l4;		// is user page table ?
#ifdef ENABLE_PTMAN
	struct list_head ptman_list;
#endif
#ifdef ENABLE_PT_RECURSIVE	// do recursive pt tracking.
	struct list_head list;
	struct list_head pt_list;	// childs
	spinlock_t temp_lock;
	int level;
	unsigned long up_index;
	struct page_table *up_pt;	// TODO: up_pt and aux can be merged..
	void *aux;			// pgd if root, and l1e_struct if leaf.
	int pt_count;
#endif
#ifdef ENABLE_PER_CACHE_PT	// light-weight cache switch
	unsigned long shadow[MAX_CACHE];
#ifdef ENABLE_REGIONING2	// light-weight mode switch
	unsigned long regioning_shadow;
#endif
#endif
};


void mark_pt(struct page_table *pt);
void unmark_pt(struct page_table *pt);

void del_pt(struct page_table *up_pt, unsigned long up_index, unsigned long mfn);
struct page_table *find_pt(unsigned long up_index, unsigned long mfn);
struct page_table *add_pt(struct page_table *up_pt, unsigned long up_index, unsigned long mfn);
struct page_dir *add_pgd(unsigned long mfn, unsigned long flag);
struct page_dir *find_pgd(unsigned long mfn, struct page_table **pt_out);
void del_pgd_common(struct page_dir *pgd);
void del_pgd(unsigned long mfn);



void flag_shadow(struct page_table *pt, int ptindex, l1_pgentry_t nl1e);
void del_shadow(struct page_table *pt, int ptindex, unsigned long mfn);
void add_shadow(struct page_table *pt, int ptindex, intpte_t l1e, unsigned int bitmap, int regioning_init_open);
void add_shadow2(struct page_table *pt, int ptindex, struct page_table *pt2);
void del_shadow_nonleaf(struct page_table *pt, int ptindex);
void add_shadow_nonleaf(struct page_table *pt, int ptindex, struct page_table *newl1, unsigned long flags);
int cr3_is_shadow(int locked);



extern struct vregion_t *last_page_touch_vr;
extern spinlock_t migrating_lock;

void l1e_mark(l1_pgentry_t *l1t, int i, struct page_table *pt, int ptindex);
void l1e_unmark(l1_pgentry_t *l1t, int i, struct page_table *pt, int ptindex, unsigned long mfn);
void l1e_open(l1_pgentry_t *l1t, int i);
void l1e_close(l1_pgentry_t *l1t, int i);
int l1e_state(l1_pgentry_t l1e);

#if 0
l2_pgentry_t l2e_mark_by_value(l2_pgentry_t l2e);
void l2e_mark(l2_pgentry_t *l2t, int i);
void l2e_unmark(l2_pgentry_t *l2t, int i);
int l2e_is_marked(l2_pgentry_t l2e);
#endif

#define CLOCK_EVENT_NEW_CR3	0
#define CLOCK_EVENT_TIMER	1
#define CLOCK_EVENT_SCHEDULE	2
#define CLOCK_EVENT_DYING_PGD		3	// not really clock event, but..
#define CLOCK_EVENT_PAUSE_TIMEOUT	4	// remove this.. probably don't need this.
#define CLOCK_EVENT_MAX		5

void do_clock(int event_nr, struct page_dir *pgd, s_time_t now);
void load_balance(void);

int would_be_idle(int from , int to);
void has_core_unbalance(int *f, int *t);

#ifdef ENABLE_MYPROF
extern int my_total_samples;
#endif
#ifdef ENABLE_HOT_PAGES
extern struct vregion_t *seed_user_hot;
extern atomic_t hetero_pages_count;
#define MAX_HETERO_VM		8
extern atomic_t hetero_pages_vm[MAX_HETERO_VM];
extern atomic_t hot_pages_vm[MAX_HETERO_VM];
extern int hetero_pages_vm_limit[MAX_HETERO_VM];
extern int vm_tot_pages[MAX_HETERO_VM];
void shrink_hot_pages(s_time_t now);
void hetero_adjust_limit(int domid, int delta);
#endif

//--------------------------------------------------------

// enabling: mini_count is set to 0, then mini_activated is set 1
// disabling: mini_disabling is set to 1, then mini_activated is set to 0, then wait mini_count to be 0, then delete all pgds, set mini_disabling to 0, and now cleanup
// all activities should check mini_activated first then increase mini_count
#define MAX_PLACE	16
extern atomic_t mini_place[MAX_PLACE];	// for debugging
extern atomic_t mini_count;	// TODO
extern int mini_activated;
extern int mini_disabling;
int check_page_touch(unsigned long addr, struct cpu_user_regs *regs);
void maybe_first_or_correction(struct page_dir *pgd);
void check_pgd(struct page_dir *pgd);
void check_vregion(struct vregion_t *vr, int option);
void del_vregion(struct vregion_t *vr);
void split_vregion(struct vregion_t *vr, struct vregion_t *to);
void merge_vregion(struct vregion_t *vr, struct vregion_t *to);

// sometimes global is reused by guest-region.. so it acts as seed region, too.
#define NEWVR_GLOBAL		(                            (1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL))|(1UL<<(VR_NO_REGIONING)))
//#define NEWVR_SEED		((1UL<<(VR_CACHEMAP_BASE+0))|(1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL)))
#define NEWVR_SEED_XEN		(                            (1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL))|(1UL<<(VR_XEN)))
#define NEWVR_SEED_KERNEL	(                            (1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL))|(1UL<<(VR_KERNEL)))
//#define NEWVR_SEED_KERNEL	((1UL<<(VR_CACHEMAP_BASE+1))|(1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL))|(1UL<<(VR_KERNEL)))
#define NEWVR_SEED_USER		(                            (1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL))|(1UL<<(VR_USER)))
//#define NEWVR_SEED_USER		((1UL<<(VR_CACHEMAP_BASE+0))|(1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL))|(1UL<<(VR_USER)))
//#define NEWVR_GUEST		(1UL<<(VR_CACHEMAP_BASE+1))
#define NEWVR_SEED_USER_HOT	(                            (1UL<<(VR_FIXED_MAP))|(1UL<<(VR_POOL))|(1UL<<(VR_USER)))
#define NEWVR_GUEST		(0)
#define NEWVR_REGULAR		((1UL<<(VR_SHRINK_NORMAP))|(1UL<<(VR_REGULAR)))
struct vregion_t *new_vregion(int loc, unsigned long flags);

void vregion_move_to_shared(struct vregion_t *vr);
void vregion_move_to_private(struct vregion_t *vr, struct page_dir *pgd);

int alloc_current_cache(struct page_dir *pgd);

void update_guest_peek(struct page_dir *pgd);
void print_guest_peek(struct page_dir *pgd);
void print_openbit_count(struct page_dir *pgd);
void mfn_check(unsigned long mfn);
void print_contention(void);
void print_all_pgd(void);
void print_vregion(struct vregion_t *vr, int flag);

#define for_each_domain_vcpu(_d,_v)	\
	for_each_domain(_d)		\
	for_each_vcpu(_d,_v)

#ifdef ENABLE_PGD
extern struct list_head pgd_list;
extern int pgd_count;
extern spinlock_t pgd_list_lock;
#endif

#ifdef ENABLE_TIMESTAMP
#define TIMESTAMP_CLEAR_ABIT	0
#define TIMESTAMP_PAGE_MIGRATE	1
#define MAX_TIMESTAMP_ID	2
#define MAX_TIMESTAMP_LOC	8
extern char *timestamp_name[MAX_TIMESTAMP_ID];	// see system_wide_init
struct timestamp_t {
	int runs[MAX_TIMESTAMP_ID], unfinished[MAX_TIMESTAMP_ID];
	s_time_t time[MAX_TIMESTAMP_ID][MAX_TIMESTAMP_LOC];
	s_time_t sum[MAX_TIMESTAMP_ID][MAX_TIMESTAMP_LOC];
	int count[MAX_TIMESTAMP_ID][MAX_TIMESTAMP_LOC];
};
DECLARE_PER_CPU(struct timestamp_t, timestamp);
void timestamp(int id, int loc);
void timestamp_start(int id);
void timestamp_end(int id, int loc);
void vtimestamp(int id, int loc);
void vtimestamp_start(int id);
void vtimestamp_end(int id, int loc);
#endif

#ifdef VERBOSE_PAGE_FAULT
extern int pf_count;
#endif



#ifdef ENABLE_TRACK_MEMLEAK
#define MAX_TRACK_MEMLEAK	16
extern atomic_t track_memleak[MAX_TRACK_MEMLEAK];	// indexed by type number
extern int track_memleak_size[MAX_TRACK_MEMLEAK];	// size of each type
#define myxmalloc_bytes(_bytes, typenr)	\
({					\
	if (typenr>=MAX_TRACK_MEMLEAK)			\
		mypanic("myxmalloc:out of range typenr");\
	atomic_inc(&track_memleak[typenr]);	\
	xmalloc_bytes(_bytes);		\
})

#define myxmalloc(_type, typenr)	\
({					\
	if (typenr>=MAX_TRACK_MEMLEAK)			\
		mypanic("myxmalloc:out of range typenr");\
	atomic_inc(&track_memleak[typenr]);	\
	xmalloc(_type);		\
})

#define myxfree(pointer, typenr)	\
({				\
	if (typenr>=MAX_TRACK_MEMLEAK)			\
		mypanic("myxfree:out of range typenr");	\
	atomic_dec(&track_memleak[typenr]);			\
	xfree(pointer);		\
})

#define myalloc_xenheap_page(typenr)	\
({				\
	if (typenr>=MAX_TRACK_MEMLEAK)			\
		mypanic("myalloc_xenheap_page:out of range typenr");\
	atomic_inc(&track_memleak[typenr]);	\
	alloc_xenheap_page();	\
})

#ifdef NO_PGD_ABOVE_4GB
#define myalloc_xenheap_page_4gb(typenr)	\
({				\
	if (typenr>=MAX_TRACK_MEMLEAK)			\
		mypanic("myalloc_xenheap_page:out of range typenr");\
	atomic_inc(&track_memleak[typenr]);	\
	alloc_xenheap_pages(0, MEMF_bits(32));	\
})
#endif

#define myfree_xenheap_page(pointer, typenr)	\
({				\
	if (typenr>=MAX_TRACK_MEMLEAK)			\
		mypanic("myfree_xenheap_page:out of range typenr");\
	atomic_dec(&track_memleak[typenr]);			\
	free_xenheap_page(pointer);	\
})
// 	cman = 0	
//	rmap_set = 1
//	vregion_t = 2
//	page_table = 3
//	page_dir = 4
//	vregion_t *[] = 5
//	vregion_t [] = 6
//	task	= 7
//	l1e_struct   = 8
//	xenheap_page for shadow = 9
//	xenheap_page for migrate_page = 10
#else
#define myxmalloc_bytes(_bytes, typenr)	xmalloc_bytes(_bytes)
#define myxmalloc(_type, typenr)	xmalloc(_type)
#define myxfree(pointer, typenr)	xfree(pointer)
#define myalloc_xenheap_page(typenr)	alloc_xenheap_page()
#define myfree_xenheap_page(pointer, typenr)	free_xenheap_page(pointer)
#endif

//	last spinlock loc : 176
//	empty loc:  174, 48, 103, 23, 79, 151,  101, 91, 87, 130, 80, 77, 78, 63, 157, 158, 86, 160, 102, 127, 96, 35, 62, 16, 73, 132, 2, 3, 132, 133, 4, 5, 61, 161, 83, 47, 54, 154, 97, 98, 112, 108, 1, 63,  
//	(vrt_lock doesn't interact with any other lock, so safe)
//	lock sequence: 
//
//	0)sync_lock
//	1)vr.lock
//
//	0)temp_lock
//	1)pgd_list_lock
//	2)pgd->lock
//	3) vr.lock
//		use vr_double_lock for locking two vr->locks  ex)merge_vregion
//	4) vregions_free_lock,cacheman[].lock,pgd->vregions_private_lock,vregions_seed_lock, pt->lock
//		use cacheman_double_lock for locking two cacheman[].lock	ex) vr_switch_density()
	// from add_rmap()
//	4-1) pt->lock
//	4-2) cacheman[].lock

//	TODO: *task* , pgd_list_lock
//
//	0) temp_lock
//	1) pgd_list_lock
//	2) pgd->lock
//	3) ptman_lock

#ifdef ENABLE_TRACK_SPINLOCK
#define MAX_TRACK_SPINLOCK	256
extern s_time_t track_spinlock_time[MAX_TRACK_SPINLOCK];
extern int track_spinlock[MAX_TRACK_SPINLOCK];
extern int track_spinlock_total[MAX_TRACK_SPINLOCK];
extern void spinlock_report(void);

#define myspin_lock_old(_lock, loc)		\
({					\
	if (!spin_trylock(_lock)) {	\
		s_time_t prev=NOW();	\
		track_spinlock[loc]++;	\
		spin_lock(_lock);	\
		track_spinlock_time[loc] += (NOW()-prev);		\
	}				\
	track_spinlock_total[loc]++;	\
})

void myspin_lock(spinlock_t *_lock, int loc);


#define myspin_trylock(_lock, loc)	\
({					\
	int ret = spin_trylock(_lock);	\
	if (ret)			\
		track_spinlock[loc]++;	\
	track_spinlock_total[loc]++;	\
	ret;				\
})
#else
#define myspin_lock(_lock, loc)		spin_lock(_lock)
#define myspin_trylock(_lock, loc)	spin_trylock(_lock)
#endif


//---------------------------------------------------------------------------
#endif
