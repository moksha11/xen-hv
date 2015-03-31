#include <xen/config.h>
#include <xen/version.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/shutdown.h>
#include <xen/nmi.h>
#include <asm/current.h>
//#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>

#include <public/callback.h>

#include <asm/spinlock.h>
#include <xen/softirq.h>
#include <mini.h>

int pcount[COUNT_MAX];
int enable_perfmon = 0;

// vregion pool
struct vregion_t *vregion_1mb_pool[MAX_VREGION_1MB_POOL];
int vregion_1mb_pool_count;
int num_vregions_per_1mb;
int hetero_hotpg_cnt;

#ifdef ENABLE_DENSITY
atomic_t abit_density_shared[MAX_CACHE][32];
#endif

#define cache_full(X) ( ACTIVE_FRAMES_CACHE(X)>cacheman[X].size/4 )

atomic_t mini_place[MAX_PLACE];	// for debugging
atomic_t mini_count;
int mini_activated;
int mini_disabling;


/* Iterated bitcount iterates over each bit. The while condition sometimes helps
   terminates the loop earlier */
int iterated_bitcount (unsigned int n)
{
    int count=0;    
    while (n)
    {
        count += n & 0x1u ;    
        n >>= 1 ;
    }
    return count ;
}

/* Precomputed bitcount uses a precomputed array that stores the number of ones
   in each char. */
static unsigned char bits_in_char [256] ;

void compute_bits_in_char (void)
{
    unsigned int i ;    
    for (i = 0; i < 256; i++)
        bits_in_char [i] = iterated_bitcount (i) ;
    return ;
}

inline int bitcount (unsigned int n)
{
    // works only for 32-bit ints
    int ret;
    ret =  bits_in_char [n         & 0xffu]
        +  bits_in_char [(n >>  8) & 0xffu]
        +  bits_in_char [(n >> 16) & 0xffu]
        +  bits_in_char [(n >> 24) & 0xffu] ;
	return ret;
}







#if 0
// from <processor.h>
struct cpuinfo_x86 {
    __u8 x86;            /* CPU family */
    __u8 x86_vendor;     /* CPU vendor */
    __u8 x86_model;
    __u8 x86_mask;
    int  cpuid_level;    /* Maximum supported CPUID level, -1=no CPUID */
    unsigned int x86_capability[NCAPINTS];
    char x86_vendor_id[16];
    char x86_model_id[64];
    int  x86_cache_size; /* in KB - valid for CPUS which support this call  */
    int  x86_cache_alignment;    /* In bytes */
    int  x86_power;
    unsigned char x86_max_cores; /* cpuid returned max cores value */
    unsigned char booted_cores;  /* number of cores as seen by OS */
    unsigned char apicid;
    unsigned short x86_clflush_size;
} __cacheline_aligned;
#endif

void myprint_cpu_info(struct cpuinfo_x86 *info)
{
	myprintk("%2x%2x%2x%2x, cpuid_level=%d, cache=%dK(?),%dalign, %dmaxcores\n", info->x86, info->x86_vendor, info->x86_model, info->x86_mask, info->cpuid_level, info->x86_cache_size, info->x86_cache_alignment, info->x86_max_cores);
}






void myprint_xenheap(void);

inline void mfn_check(unsigned long mfn)
{
#ifdef DEBUG_ASSERT
	if (mfn >= max_page) {
		myprintk("mfn_check:invalid mfn 0x%x(%d), max_page:%d, are you using video-card? set runlevel to 3\n", mfn, mfn, max_page);
		mypanic("mfn_check");
	}
//	MYASSERT(!(mfn & pfn_hole_mask));
	MYASSERT(!pfn_hole_mask);
	if (!(
           likely(test_bit(pfn_to_pdx(mfn) / PDX_GROUP_COUNT,
                           pdx_group_valid))
		)) {
		myprintk("mfn_check:invalid mfn 0x%x(%d), test_bit(%d/%d , pdx_group_valid) fail\n", mfn, mfn, pfn_to_pdx(mfn), PDX_GROUP_COUNT);
		mypanic("mfn_check");
	}
#endif
}



#ifdef ENABLE_HISTOGRAM
// grep vr->count_lock before calling this
inline void vr_inc_density(struct vregion_t *vr, int i, int cache)
{
#ifdef DEBUG_ASSERT
	if (i<0 || i>32)		mypanic("i<0||i>32");
	if (cache<0 || cache>=MAX_CACHE)	mypanic("cache<0||cache>=MAX_CACHE");
	if (!spin_is_locked(&vr->count_lock))		mypanic("inc_density:get vr->count_lock first!");
#endif
	if (i==32)
		i = 31;

	vr->abit_histogram[cache][i]++;
#ifdef DEBUG_ASSERT
	if (!vr->abit_histogram[cache][i])
		mypanic("WARN: vr_inc_density overflow?");
#endif
#ifdef ENABLE_CACHEMAN1
	myspin_lock(&cacheman[cache].lock, 125);
	if (is_vregion_cache_in(vr, cache)) {
		cacheman[cache].abit_density[i]++;
#ifdef DEBUG_ASSERT
		if (!cacheman[cache].abit_density[i])
			mypanic("WARN: vr_inc_density cache density overflow?\n");
#endif
		if (vr->pgd) {
#ifdef DEBUG_ASSERT
			if (test_bit(VR_SHARED_PAGE, &vr->flags))
				mypanic("vr_inc_density!!");
#endif
			atomic_inc(&vr->pgd->abit_density[cache][i]);
#ifdef DEBUG_ASSERT
			if (!atomic_read(&vr->pgd->abit_density[cache][i]))
				mypanic("WARN: vr_inc_density pgd->density overflow?\n");
#endif
		} else {
#ifdef DEBUG_ASSERT
			if (!test_bit(VR_SHARED_PAGE, &vr->flags))
				mypanic("vr_inc_density!!");
#endif
			atomic_inc(&abit_density_shared[cache][i]);
#ifdef DEBUG_ASSERT
			if (!atomic_read(&abit_density_shared[cache][i]))
				mypanic("WARN: vr_inc_density shared pgd->density overflow?\n");
#endif
		}
	}
	spin_unlock(&cacheman[cache].lock);
#endif
}
// grep vr->count_lock before calling this
inline void vr_dec_density(struct vregion_t *vr, int i, int cache)
{
#ifdef DEBUG_ASSERT
	if (i<0 || i>32)		mypanic("i<0||i>32");
	if (cache<0 || cache>=MAX_CACHE)	mypanic("cache<0||cache>=MAX_CACHE");
	if (!spin_is_locked(&vr->count_lock))		mypanic("dec_density:get vr->count_lock first!");
#endif
	if (i==32)
		i = 31;
#ifdef DEBUG_ASSERT
	if (!vr->abit_density[cache][i]) {
		myprintk("underflow, i=%d,$%d\n", i, cache);
		print_vregion(vr, VRPRINT_RMAP);
		mypanic("WARN: vr_dec_density going -1?");
	}
#endif
	vr->abit_density[cache][i]--;
#ifdef ENABLE_CACHEMAN1
	myspin_lock(&cacheman[cache].lock, 126);
	if (is_vregion_cache_in(vr, cache)) {
#ifdef DEBUG_ASSERT
		if (!cacheman[cache].abit_density[i])
			mypanic("WARN: vr_dec_density cache density going -1?\n");
#endif
		cacheman[cache].abit_density[i]--;
		if (vr->pgd) {
#ifdef DEBUG_ASSERT
			if (test_bit(VR_SHARED_PAGE, &vr->flags))
				mypanic("vr_dec_density!!");
#endif
#ifdef DEBUG_ASSERT
			if (!atomic_read(&vr->pgd->abit_density[cache][i])) {
				myspin_lock(&vr->lock,155);
				print_vregion(vr, VR_PRINT_RMAP);
				spin_unlock(&vr->lock);
				mypanic("WARN: vr_dec_density pgd->density going -1?\n");
			}
#endif
			atomic_dec(&vr->pgd->abit_density[cache][i]);
		} else {
#ifdef DEBUG_ASSERT
			if (!test_bit(VR_SHARED_PAGE, &vr->flags))
				mypanic("vr_dec_density!!");
#endif
#ifdef DEBUG_ASSERT
			if (!atomic_read(&abit_density_shared[cache][i]))
				mypanic("WARN: vr_dec_density shared pgd->density going -1?\n");
#endif
			atomic_dec(&abit_density_shared[cache][i]);
		}
	}
	spin_unlock(&cacheman[cache].lock);
#endif
}
// don't need vr->count_lock...
inline void vr_reset_density(struct vregion_t *vr, int i, int cache)
{
#ifdef DEBUG_ASSERT
	if (i<0 || i>31)		mypanic("i<0||i>31");
	if (cache<0 || cache>=MAX_CACHE)	mypanic("cache<0||cache>=MAX_CACHE");
#endif
	vr->abit_density[cache][i] = 0;
}

// grep vr->count_lock before calling this
inline void vr_move_density(struct vregion_t *vr, int from, int to, int cache)
{
#ifdef DEBUG_ASSERT
	if (from<0 || from>32)		mypanic("from<0||from>32");
	if (to<0 || to>32)		mypanic("to<0||to>32");
	if (cache<0 || cache>=MAX_CACHE)	mypanic("cache<0||cache>=MAX_CACHE");
	if (!spin_is_locked(&vr->count_lock))		mypanic("move_density:get vr->count_lock first!");
#endif
	if (from==32)
		from = 31;
	if (to==32)
		to = 31;
#ifdef DEBUG_ASSERT
	if (!vr->abit_density[cache][from]) {
		myprintk("underflow, from=%d,$%d\n", from, cache);
		print_vregion(vr,VRPRINT_RMAP);
		mypanic("WARN: vr_move_density going -1?");
	}
#endif
	vr->abit_density[cache][from]--;
	vr->abit_density[cache][to]++;
#ifdef DEBUG_ASSERT
	if (!vr->abit_density[cache][to])
		mypanic("WARN: vr_move_density overflow?");
#endif
#ifdef ENABLE_CACHEMAN1
	myspin_lock(&cacheman[cache].lock, 129);
	if (is_vregion_cache_in(vr, cache)) {
#ifdef DEBUG_ASSERT
		if (!cacheman[cache].abit_density[from])
			mypanic("WARN: vr_move_density cache density going -1?\n");
#endif
		cacheman[cache].abit_density[from]--;
		cacheman[cache].abit_density[to]++;
#ifdef DEBUG_ASSERT
		if (!cacheman[cache].abit_density[to])
			mypanic("WARN: vr_move_density cache density overflow?\n");
#endif
		if (vr->pgd) {
#ifdef DEBUG_ASSERT
			if (test_bit(VR_SHARED_PAGE, &vr->flags))
				mypanic("vr_move_density!!");
#endif
#ifdef DEBUG_ASSERT
			if (!atomic_read(&vr->pgd->abit_density[cache][from]))
				mypanic("WARN: vr_move_density pgd->density going -1?\n");
#endif
			atomic_dec(&vr->pgd->abit_density[cache][from]);
			atomic_inc(&vr->pgd->abit_density[cache][to]);
#ifdef DEBUG_ASSERT
			if (!atomic_read(&vr->pgd->abit_density[cache][to]))
				mypanic("WARN: vr_move_density pgd->density overflow?\n");
#endif
		} else {
#ifdef DEBUG_ASSERT
			if (!test_bit(VR_SHARED_PAGE, &vr->flags))
				mypanic("vr_move_density!!");
#endif
#ifdef DEBUG_ASSERT
			if (!atomic_read(&abit_density_shared[cache][from]))
				mypanic("WARN: vr_move_density shared pgd->density going -1?\n");
#endif
			atomic_dec(&abit_density_shared[cache][from]);
			atomic_inc(&abit_density_shared[cache][to]);
#ifdef DEBUG_ASSERT
			if (!atomic_read(&abit_density_shared[cache][to]))
				mypanic("WARN: vr_move_density shared pgd->density overflow?\n");
#endif
		}
	}
	spin_unlock(&cacheman[cache].lock);
#endif
}
/*


void cacheman_double_lock(int c1, int c2)
{
#ifdef DEBUG_ASSERT
	MYASSERT(c1 != c2);
	MYASSERT(c1 >=0 && c1 <MAX_CACHE);
	MYASSERT(c2 >=0 && c2 <MAX_CACHE);
#endif
	if (c1 <= c2) {
		myspin_lock(&cacheman[c1].lock, 146);
		myspin_lock(&cacheman[c2].lock, 147);
	} else {
		myspin_lock(&cacheman[c2].lock, 148);
		myspin_lock(&cacheman[c1].lock, 149);
	}
}

void cacheman_double_unlock(int c1, int c2)
{
#ifdef DEBUG_ASSERT
	MYASSERT(c1 != c2);
	MYASSERT(c1 >=0 && c1 <MAX_CACHE);
	MYASSERT(c2 >=0 && c2 <MAX_CACHE);
#endif
	if (c1 <= c2) {
		spin_unlock(&cacheman[c1].lock);
		spin_unlock(&cacheman[c2].lock);
	} else {
		spin_unlock(&cacheman[c2].lock);
		spin_unlock(&cacheman[c1].lock);
	}
}


// get vr->lock before call this (for rmaps traversing)
// grep vr->count_lock before calling this
inline void vr_switch_density(struct vregion_t *vr, int c1, int c2)
{
	int i,count = 0;
	unsigned long v;
#ifdef DEBUG_ASSERT
	if (c1<0 || c1>=MAX_CACHE)	mypanic("c1<0||c1>=MAX_CACHE");
	if (c2<0 || c2>=MAX_CACHE)	mypanic("c2<0||c2>=MAX_CACHE");
	if (!spin_is_locked(&vr->lock))		mypanic("switch_density:get vr->lock first!");
	if (!spin_is_locked(&vr->count_lock))		mypanic("switch_density:get vr->count_lock first!");
#endif
	cacheman_double_lock(c1, c2);	// make sure c1,c2 is not in any cacheman
	if (is_vregion_cache_in(vr, c1)) {
		cache_out(vr, c1);
		cache_out_density(vr, c1);
		myprintk("Info switch_density: $%d is cache-in, so cache-out it\n", c1);
	}
	if (is_vregion_cache_in(vr, c2)) {
		cache_out(vr, c2);
		cache_out_density(vr, c2);
		myprintk("Info switch_density: $%d is cache-in, so cache-out it\n", c2);
	}
#ifdef DEBUG_ASSERT
	if (test_bit(VR_SHARED_PAGE, &vr->flags)) {
		mypanic("switch_density : shared vr?\n");
	}
#endif
	for(i=0;i<32;i++) {
		v = vr->abit_density[c1][i];
		vr->abit_density[c1][i] = vr->abit_density[c2][i];
		vr->abit_density[c2][i] = v;
	}

	struct rmap_set *rms;
	unsigned long mfn;
	list_for_each_entry(rms, &vr->rmaps_list, list) {
	for(i=0;i<rms->size;i++) {
		if (rms->rmaps[i].pt) {
#ifdef DEBUG_ASSERT
			count++;
#endif
			mfn = rms->rmaps[i].mfn;
			v = ABIT_HISTORY(mfn, c1);
			ABIT_HISTORY(mfn, c1) = ABIT_HISTORY(mfn, c2);
			ABIT_HISTORY(mfn, c2) = v; 
		}
	}
	}
#ifdef DEBUG_ASSERT
	if (count != vr->frame_count) {
		myprintk("WARN! switch_density fcnt: %d != %d ? rcnt=%d\n", count, vr->frame_count, vr->rmap_count[todo]);
		print_vregion(vr, 0);
	}
#endif

	cacheman_double_unlock(c1, c2);
}
*/
#endif



#ifdef DEBUG_HISTOGRAM	// for debugging
spinlock_t hist_lock;
#define MAX_HISTOGRAM	2560	// this is more than enough
struct histogram_entry {
	unsigned int abit_history;
	unsigned int count;
	struct histogram_entry *next;
} hentry[MAX_HISTOGRAM];
struct histogram_entry *hfree;
struct histogram_entry *hlist;

void init_hist(void)
{
	int i;
	hlist = NULL;
	hfree = &hentry[0];
	for(i=0;i<MAX_HISTOGRAM;i++) {
		hentry[i].abit_history = hentry[i].count = 0;
		hentry[i].next = &hentry[i+1];
	}
	hentry[i-1].next = NULL;
}

void add_hist(unsigned int abit_history)
{
	struct histogram_entry *i = hlist, *pre_i;
	if (!i) {
		if (!hfree) {
			mypanic("increase MAX_HISTOGRAM!\n");
		}
		hlist = hfree;
		hlist->abit_history = abit_history;
		hlist->count = 1;
		hfree = hfree->next;
		hlist->next = NULL;
		return;
	}
	while (i) {
		if (i->abit_history == abit_history) {
			i->count++;
			return;
		}
		pre_i = i;
		i = i->next;
	}


	if (!hfree) {
		mypanic("increase MAX_HISTOGRAM!\n");
	}
	i = hfree;
	hfree = hfree->next;
	i->next = NULL;
	pre_i->next = i;
	i->abit_history = abit_history;
	i->count = 1;
}

struct histogram_entry *get_hist(void)
{
	struct histogram_entry *i = hlist, *ret = NULL;
	int large = 0;
	while(i) {
		if (i->count > large && i->abit_history) {
			ret = i;
			large = i->count;
		}
		i = i->next;
	}
	return ret;
}

void print_hist(void)
{
	struct histogram_entry *i = hlist;
	while(i) {
		myprintk("abit:%8x count:%d\n", i->abit_history, i->count);
		i = i->next;
	}
}
#endif


//-----------------------------------------------------------

void printx_vregion(struct vregion_t *vr)
{
	struct list_head *k;
	struct rmap_set *rms;
	int i,j;
	unsigned long array[128];
	int count = 0;

//	myspin_lock(&vr->count_lock, 67);
//	myprintk("count:$:%d rmap:%d frame:%d, flag:0x%2x\n", vr->cache_count, vr->rmap_count, vr->frame_count, vr->flags);
	array[count++] = 0;//vr->pgd;
	array[count++] = cachemap_count(vr);
	array[count++] = vr->rmap_count[0];
	array[count++] = vr->frame_count;
	array[count++] = vr->flags;
#ifdef ENABLE_CLOCK_OLD
	for(j=0;j<MAX_CACHE;j++) {
		for(i=0;i<32;i++)
			array[count++] = vr->abit_density[j][i];
	}
#endif

//	spin_unlock(&vr->count_lock);
//	myspin_lock(&vr->lock, 68);
/*
	list_for_each_entry(rms, &vr->rmaps_list, list) {
		myprintk("(rms:%d/%d/%d)\n", rms->flag_count, rms->entry_count, rms->size);
		for(i=0;i<rms->size;i++) {
			if (rms->rmaps[i].pt)
				myprintk("(vr:%x pgd:%x ptmfn:%x pti:%3x mfn:%3x f:%x)\n", vr, rms->rmaps[i].pt->pgd,  rms->rmaps[i].pt->mfn, rms->rmaps[i].ptindex, rms->rmaps[i].mfn, rms->rmaps[i].flag);
		}
	}
*/
//	spin_unlock(&vr->lock);
//	myspin_lock(&vr->count_lock, 69);
/*
	for(i=0;i<MAX_CACHE;i++)
		if (list_empty(&vr->list[i])) {
			printk("$%d=empty, ", i);
		} else {
			printk("$%d=Nonempty, ", i);
		}
*/
//	spin_unlock(&vr->count_lock);
	MYXTRACE(TRC_MIN_VREGION, count, array);
}



void print_vregion(struct vregion_t *vr, int flag)
{
	struct list_head *k;
	int i,j;
#ifdef ENABLE_REGIONING3
	s_time_t now = NOW();
#endif
//	myspin_lock(&vr->count_lock, 67);
	myprintk("vr:%p "
		"rmap:%d,%d frame:%d "
//		"head:%d "
#ifdef ENABLE_REGIONING3
		"acs:%lldus d:%lldus "
#endif
//		"last:[%lldus,%lldus] "
		"flag:0x%2x "
//		"u:%p,%p "
#ifdef ENABLE_DENSITY
		"active:[%d,%d]"
#endif
		"\n", vr, 
		vr->rmap_count[RMAPS_USER], vr->rmap_count[RMAPS_KERNEL], vr->frame_count,
//		vr->head, 
#ifdef ENABLE_REGIONING3
		vr->access/1000LL, 
		(now - vr->tpoint)/1000LL,
#endif
//		vr->last_access[0]/1000LL, vr->last_access[1]/1000LL, 
		vr->flags
//		, vr->u.inuse.cman, vr->u.inuse.empty
#ifdef ENABLE_DENSITY
		,ACTIVE_FRAMES_VR(vr, 0), ACTIVE_FRAMES_VR(vr, 1)
#endif
		);
#if 0
	myprintk("refcnt:");
	for(i=0;i<MAX_VR_REFCNT;i++)
		printk("%d,",atomic_read(&vr->vr_refcnt[i]));
	printk("\n");
#endif

#ifdef ENABLE_DENSITY
	if (flag & VRPRINT_DENSITY) {
/*
		for(j=0;j<MAX_CACHE;j++) {
			myprintk("density$%d:", j);
			for(i=0;i<32;i++)
				printk("%d, ", vr->abit_density[j][i]);
			printk("\n");
		}
*/
	} else {
//		spin_unlock(&vr->count_lock);
		return;
	}
#endif

//	spin_unlock(&vr->count_lock);

#ifdef ENABLE_RMAP
	if (flag & VRPRINT_RMAP) {
		print_rmaps(vr);
	}
#endif
}


#ifdef DEBUG_CHECK_VREGION
//#define MAX_MFN_LIST	2560		// must be >= MAX_PAGES_IN_VREGION
#define MAX_MFN_LIST 65530
struct mfn_list_t {
	unsigned long mfn_list[MAX_MFN_LIST];
};

void add_mfn(unsigned long mfn, unsigned long *mfn_list)
{
	int i;
	for(i=0;i<MAX_MFN_LIST;i++) {
		if (mfn_list[i] == mfn)
			return;
	}
	for(i=0;i<MAX_MFN_LIST;i++) {
		if (!mfn_list[i]) {
			mfn_list[i] = mfn;
			return;
		}
	}
	mypanic("add_mfn: full?");
}

int count_mfn_list(unsigned long *mfn_list)
{
	int i, count=0;
	for(i=0;i<MAX_MFN_LIST;i++)
		if (mfn_list[i])
			count++;
	return count;
}

// get vr->lock before call this
// if option!=0, check if private vr has only one cache
void check_vregion(struct vregion_t *vr, int option)
{
	this is old code..
#if 1 // old code..
	MYASSERT(spin_is_locked(&vr->lock));
	pcount[COUNT_CHECK_VREGION]++;
	struct rmap_set *rms;
	struct page_dir *pgd = NULL;
	int i, j;
	int count = 0, count_sub = 0, is_shared = 0;
	struct mfn_list_t *mfn_list = myxmalloc(struct mfn_list_t, TODO);

	for(i=0;i<MAX_MFN_LIST;i++)
		mfn_list->mfn_list[i] = 0;

	list_for_each_entry(rms, &vr->rmaps_list, list) {
		count_sub = 0;
		for(i=0;i<rms->size;i++) {
			if (!rms->rmaps[i].pt)
				continue;
			count++;
			count_sub++;
			add_mfn(rms->rmaps[i].mfn, &mfn_list->mfn_list[0]);
			if (pgd == NULL) {
				pgd = rms->rmaps[i].pt->pgd;
				continue;
			}
			if (pgd != rms->rmaps[i].pt->pgd) {
				// shared
				is_shared = 1;
				if (!test_bit(VR_SHARED_PAGE, &vr->flags)) {
					print_vregion(vr, VRPRINT_RMAP);
					mypanic("Shared flag should be on.\n");
				}
			}
		}
		if (count_sub==0 && rms != &vr->default_rmaps)
			myprintk("empty rmap_set exists??");
	}
	if (vr->rmap_count[todo] != count)
		myprintk("vr->rmap_count %d,%d != real %d\n", vr->rmap_count[RMAPS_USER], vr->rmap_count[RMAPS_KERNEL], count);
	if (vr->frame_count != count_mfn_list(&mfn_list->mfn_list[0]))
		myprintk("vr->frame_count %d!=real %d\n", vr->frame_count, count_mfn_list(&mfn_list->mfn_list[0]));
	if (!is_shared && test_bit(VR_SHARED_PAGE, &vr->flags)) {
		print_vregion(vr, VRPRINT_RMAP);
		mypanic("Shared flag should be off!.\n");
	}
	myxfree(mfn_list, 9);
	if (test_bit(VR_SHARED_PAGE, &vr->flags)) {
		if (vr->rmap_count[todo] < 2)
			myprintk("Shared but rmap_count<2 \n");
	} else {
#ifdef DEBUG_ASSERT
	if (test_bit(VR_ONECACHE, &vr->flags)) {
#if 1 // old code
		if (option && !test_bit(VR_MIGRATING, &vr->flags) && cachemap_count(vr)>1) {
			print_vregion(vr, VRPRINT_RMAP);
			myprintk("Private vr has %d caches mapped!\n", cachemap_count(vr) );
		}
#endif
	}
#endif
	}

#ifdef ENABLE_DENSITY
	int sum;
	for(j=0;j<MAX_CACHE;j++) {
		sum = 0;
		for(i=0;i<32;i++) {
			sum += vr->abit_density[j][i];
		}
		if (sum != vr->frame_count)
			myprintk("density sum:%d != #frame:%d for $%d!\n", sum, vr->frame_count, j);
	}
#endif
#endif
}
#else
void check_vregion(struct vregion_t *vr, int option) {}
#endif

#ifdef VERBOSE_PAGE_TABLE_MARKING
int check_pt_rmap_shared(struct page_table *pt)
{
	struct list_head *i,*k, *k2;
	struct vregion_t *vr;
	struct rmap *rm;
	int ret = 0, j;

	// TODO: also check private_vr in each page_dir
	// vregions_shared_lock?
	list_for_each_entry(vr, &vregions_shared, global_list) {
		// vr->lock?
		list_for_each_safe(k, k2, &vr->rmap_list) {
			rm = list_entry(k, struct rmap, list);
			if (rm->pt == pt) {
				myprintk("REMAIN [pgmfn=%x,ptmfn=%x,pti=%d]\n",rm->pt->pgd->mfn, rm->pt->mfn, rm->ptindex);
				ret++;
			} else if (rm->pt->mfn == pt->mfn) {
				myprintk("BUG!! rm->pt!=pt but rm->pt->mfn==pt->mfn?? !\n");
			}
		}
	}

	return ret;
}
#endif
#ifdef DEBUG_CHECK_RMAP
void verify_rmap(struct rmap_entry *rme)
{
	l1_pgentry_t l1e, *l1t;

	l1t = map_domain_page(rme->pt->mfn);
	l1e = l1t[rme->ptindex];

	if (!(l1e_get_flags(l1e) & _PAGE_PRESENT)) {
		myprintk("verify: L1 doesn't exist! rme->pt->mfn:%x[%d] but l1e=%x\n", rme->pt->mfn, rme->ptindex, l1e.l1);
		mypanic("verify");
	}
	if (l1e_get_pfn(l1e) != rme->mfn) {
		myprintk("verify: l1e=%x, rme->mfn:%x\n", l1e.l1, rme->mfn);
		mypanic("verify");
	}
	unmap_domain_page(l1t);
}

void verify_rmap_entry(struct rmap_set *rms)
{
	int i;
	for(i=0;i<rms->size;i++) {
		if (rms->rmaps[i].pt) {
			verify_rmap(&rms->rmaps[i]);			
		}
	}

}


void verify_shared_rmap(void)
{
	struct vregion_t *vr;
	struct rmap_set *rms;

	// TODO: do vregions_private, too
	// need lock for vregions_shared?
	list_for_each_entry(vr, &vregions_shared, global_list) {
		// vr->lock?
		list_for_each_entry(rms, &vr->rmaps_list, list) {
			verify_rmap_entry(rms);
		}
	}
}
#else
void verify_shared_rmap(void) {}
#endif

void print_pt(struct page_table *pt)
{
#ifdef ENABLE_PT_RECURSIVE
	myprintk("lvl:%d mfn:%x(%d), up(pt:%x i:%x) pt_count:%d aux:%lx\n", pt->level, pt->mfn, pt->user_l4, pt->up_pt, pt->up_index, pt->pt_count, pt->aux);
#else
	myprintk("mfn:%x(%d)\n", pt->mfn, pt->user_l4);
#endif
}


int cache_find_emptiest(void)
{
	int min = 999999, ret = -1, i, active_frames;
	for(i=0;i<MAX_CACHE;i++) {
		active_frames = ACTIVE_FRAMES_CACHE(i);
		if (active_frames < min) {
			min = active_frames;
			ret = i;
		}
	}
#ifdef DEBUG_ASSERT
	if (ret == -1)
		mypanic("ret==-1");
#endif
	return ret;
}

// allocate current cache to first cache
int initial_cache_current(struct page_dir *pgd)
{
	return cache_now;
}

// allocate initial cache to first cache
int initial_cache_last(struct page_dir *pgd)
{
	return MAX_CACHE-1;
}

// allocate initial cache to last cache
int initial_cache_first(struct page_dir *pgd)
{
	return 0;
}

// allocate initial cache
int initial_cache_emptiest(struct page_dir *pgd)
{
	return cache_find_emptiest();
}

// allocate initial cache
int initial_cache_alt(struct page_dir *pgd)
{
	int ret;

	static int alt = 0;
	alt++;
	if (alt>=MAX_CACHE)
		alt = 0;
	ret = alt;

#ifdef VERBOSE_ALLOC_CURRENT_CACHE
	myprintk("pgdmfn:%x alloc'ed to $%d\n", pgd->mfn, ret);
#endif
#ifdef DEBUG_ASSERT
	if (!(ret>=0 && ret<MAX_CACHE)) {
		myprintk("!!");
		mypanic("panic");
	}
#endif
	return ret;
}

#if 0
// testing code
void mybits(void)
{
	unsigned long mybits[2][BITS_TO_LONGS(1024)];
	printk("size:%d=%d*2, %x=%x, %x\n", sizeof(mybits), sizeof(mybits[0]), mybits, mybits[0], mybits[1] );

	bitmap_zero(mybits[0], 1024);
	bitmap_zero(mybits[1], 1024);
	mybits[1][3] = 0xa;

	unsigned int  pos;

	for ( pos = find_first_bit(mybits[1], 1024);
		pos < 1024;
		pos = find_next_bit(mybits[1], 1024, pos+1) )
	{
		printk("%d=set, ", pos);
	}
	printk("\n");

	test_and_set_bit( 96, mybits[1]);

	for ( pos = find_first_bit(mybits[1], 1024);
		pos < 1024;
		pos = find_next_bit(mybits[1], 1024, pos+1) )
	{
		printk("%d=set, ", pos);
	}
	printk("\n");

	test_and_clear_bit( 97, mybits[1]);

	for ( pos = find_first_bit(mybits[1], 1024);
		pos < 1024;
		pos = find_next_bit(mybits[1], 1024, pos+1) )
	{
		printk("%d=set, ", pos);
	}
	printk("\n");

	int i;
	for( i=0;i<1024;i++) {
		if ( test_bit(i, mybits[1]) ) {
			printk("%d, ",i);
		}
	}
	printk("\n");
}
#endif

#if 0
void mybits(void)
{
	unsigned long flags = 0;
	int old;

	printk("flags:%x\n", flags);
	old = test_and_set_bit(VR_SHARED_PAGE, &flags);
	printk("old:%x, flags:%x\n", old, flags);
	old = test_and_set_bit(VR_SHARED_PAGE, &flags);
	printk("old:%x, flags:%x\n", old, flags);
	old = test_and_clear_bit(VR_SHARED_PAGE, &flags);
	printk("old:%x, flags:%x\n", old, flags);
	old = test_and_clear_bit(VR_SHARED_PAGE, &flags);
	printk("old:%x, flags:%x\n", old, flags);
	old = test_and_set_bit(VR_SHARED_PAGE, &flags);
	printk("old:%x, flags:%x\n", old, flags);
	old = test_and_clear_bit(VR_SHARED_PAGE, &flags);
	printk("old:%x, flags:%x\n", old, flags);
}
#endif





#ifdef ENABLE_BINPACKING
DEFINE_PER_CPU(s_time_t, cosched_flagtime);
DEFINE_PER_CPU(struct page_dir *, cosched_expected);
#endif
DEFINE_PER_CPU(unsigned long, locked_pt);
DEFINE_PER_CPU(unsigned long, found_pt);
DEFINE_PER_CPU(unsigned long, locked_pt_loc);
spinlock_t temp_lock;



int clock_period_ms;
char *machine_name;
int max_proc;
int max_cache;
int proc2intcache[MAX_PROC];
cpumask_t cache2cpumask[MAX_CACHE];

void print_config(void)
{
	myprintk("Machine=%s, %d CPUs(MAX:%d), %d caches(MAX:%d), sizeof(vr)=%d\n", machine_name, max_proc, MAX_PROC, max_cache, MAX_CACHE, sizeof(struct vregion_t));
}

void system_wide_destroy(void)
{
	myprintk("system_wide_destory start..\n");
	// destroy vrt first because set_vrt() assumes grt would hold reference to vr..
#ifdef ENABLE_VREGIONS
	if (mytable) {	// if allocated, or not-used
		vrt_destroy();
	}
#endif

#ifdef ENABLE_VREGIONS
	// del vregion pools
	int i;
	if (vregions_free_count != num_vregions_per_1mb*vregion_1mb_pool_count)
		myprintk("Warn! vregions_free_count:%d != original:%d\n", vregions_free_count, num_vregions_per_1mb*vregion_1mb_pool_count);
	for(i=0;i<vregion_1mb_pool_count;i++) {
		myxfree(vregion_1mb_pool[i], 6);
	}
	if (vregions_xmalloc_count)
		myprintk("WARN! Due to empty vregions_free,called xmalloc %d times. Increase pool size!\n", vregions_xmalloc_count);
#endif
	memleak_report();
	myprintk("end of system_wide_destroy\n");
}

char cpustr[1024];
void print_pcpus()
{
	int cpu;
	for_each_cpu_mask(cpu, cpu_online_map) {
		myprintk("pcpu%d: ", cpu);
/* representing HT siblings of each logical CPU */
    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_sibling_map, cpu));
    printk("sibling=%s, ", cpustr);
/* representing HT and core siblings of each logical CPU */
    cpumask_scnprintf(cpustr, sizeof(cpustr), per_cpu(cpu_core_map, cpu));
    printk("core=%s\n", cpustr);
		break;
	}

	myprintk("max_page = %ld (%ldM)\n", max_page, max_page*4/1024);
	myprintk("max_pdx  = %ld (%ldM)   pfn_pdx_hole_shift  = %d\n", max_pdx, max_pdx*4/1024, pfn_pdx_hole_shift );
	myprintk("total_pages = %ld (%ldM)\n", total_pages, total_pages*4/1024);
	// no pfn compression
	MYASSERT(max_pdx == max_page);
	MYASSERT(pfn_pdx_hole_shift == 0);
}
#ifdef ENABLE_TIMESTAMP
char *timestamp_name[MAX_TIMESTAMP_ID];	// see system_wide_init
#endif
void system_wide_init(void)
{
	int i;
	atomic_set(&mini_count, 0);	// maybe unnecessary, but..
	print_pcpus();
	for(i=0;i<MAX_CACHE;i++) {
		cpus_clear(cache2cpumask[i]);
	}
	for(i=0;i<MAX_PROC;i++) {
		proc2intcache[i] = -1;
	}
#ifdef ENABLE_TIMESTAMP
	timestamp_name[0] = "clear_abit";
	timestamp_name[1] = "page_migrate";
#endif
	myprintk("cpuid_level : %d\n", cpu_data[0].cpuid_level);
#ifdef ENABLE_ASYMMETRIC_CACHE
#error TODO
#else
#ifndef ONECACHE
	if (cpu_data[0].cpuid_level == 10) {
		clock_period_ms = 100;
		machine_name = "piquet";
		max_proc = 4;
		max_cache = 2;
		proc2intcache[0] = 0;
		proc2intcache[1] = 0;
		proc2intcache[2] = 1;
		proc2intcache[3] = 1;
		cpu_set(0, cache2cpumask[0]);
		cpu_set(1, cache2cpumask[0]);
		cpu_set(2, cache2cpumask[1]);
		cpu_set(3, cache2cpumask[1]);
	} else if (cpu_data[0].cpuid_level == 11) {
		clock_period_ms = 100;
		machine_name = "westmere";
		max_proc = 32;
		max_cache = 4;
		int i;
		for(i=0;i<8;i++) {
			proc2intcache[i] = 0;
			cpu_set(i, cache2cpumask[0]);
		}
		for(i=8;i<16;i++) {
			proc2intcache[i] = 1;
			cpu_set(i, cache2cpumask[1]);
		}
		for(i=16;i<24;i++) {
			proc2intcache[i] = 2;
			cpu_set(i, cache2cpumask[2]);
		}
		for(i=24;i<32;i++) {
			proc2intcache[i] = 3;
			cpu_set(i, cache2cpumask[3]);
		}
	} else {
		mypanic("cannot determine machine...TODO\n");
	}
#else
	{
		clock_period_ms = 100;
		machine_name = "Vishal's machine";
		max_proc = 0;
		max_cache = 1;
		int cpu;
		for_each_cpu_mask(cpu, cpu_online_map) {
			proc2intcache[cpu] = 0;
			cpu_set(cpu, cache2cpumask[0]);
			max_proc++;
		}
	}
#endif
#endif

#ifdef ENABLE_MEASURE_UNBALANCE
	for(i=0;i<MAX_CACHE;i++) {
		atomic_set(&cacheman[i].vcpu_count , 0);
	}
#endif
	// information above is needed by vcpu_count, so that's why they're here.

#ifdef ENABLE_PGD
	init_pgds();
#endif
#ifdef ENABLE_TRACK_MEMLEAK
	init_track_memleak();
#endif
#ifdef ENABLE_TRACK_SPINLOCK
	init_track_spinlock();
#endif
#ifdef ENABLE_VREGIONS
	init_vregion_pools();
#endif
#ifdef ENABLE_TRACK_MEMLEAK
	init_track_memleak_size();
#endif
	init_mytable();	// need this here to enable guest-defined region
#ifdef ENABLE_VREGIONS
	if (mytable)	// if allocated, or not-used
		vrt_init();	// this requires new_vregion
#endif
#ifdef REGIONING_TEMP
	regioning_init();
#endif
#ifdef ENABLE_HETERO
	hetero_initialize();
#endif
}



void _enable_soft_cache(void *info)
{
	int cpu = smp_processor_id();
	myprintk("CPU%d: enabled\n", cpu);
}

struct heap_frame_t *mytable;

void init_mytable(void)
{
	if (!sizeof(struct heap_frame_t)) {	// no use of mytable.. it's fine.
		myprintk("mytable is not used.\n");
		mytable = -1;	// poison
		return;
	}
	myprintk("max_page:%d * entry size:%d = mytable size:%d\n", max_page, sizeof(struct heap_frame_t), sizeof(struct heap_frame_t)*max_page);
	mytable = myxmalloc_bytes( sizeof(struct heap_frame_t)*max_page, 5 );
	if (mytable) {
		memset(mytable, 0, sizeof(struct heap_frame_t)*max_page);
		myprintk("mytable located at %p\n", mytable);
		return;
	}
	mypanic("WARN mytable allocation failed!?!?\n");
}

unsigned long enable_soft_cache(void)
{
	int i,j ;
//	mybits();
//	return ret;

	struct vcpu *v;
	struct domain *d;

	if (!max_proc) {
		myprintk("WARN! enabling cancelled...unknown machine..\n");
		return 1;
	}
	myprintk("==================== SOFT CACHE ENABLED ====================\n");

	MYASSERT(_PAGE_GUEST_KERNEL != 0);

	rcu_read_lock(&domlist_read_lock);
	for_each_domain(d) {
		myprintk("d%d.arch.paging.mode:%x enabled:%x, shadow:%x, hap:%x\n", d->domain_id, d->arch.paging.mode, paging_mode_enabled(d), paging_mode_shadow(d), paging_mode_hap(d));
		myprintk("d%d->vm_assist:%x (1:full-4GB-seglimit, 2:4gb_segnotify, 4:writablePT, 8:PDPTs above 4gb(x86/PAE guest)\n", d->domain_id, d->vm_assist);
		paging_dump_domain_info(d);
		MYASSERT(!(d->arch.paging.mode));	// for now..
		for_each_vcpu(d,v) {
//			myprintk("v%d:  ", v->vcpu_id);
			paging_dump_vcpu_info(v);
		}
	}
	rcu_read_unlock(&domlist_read_lock);

	myprint_xenheap();
	print_pcpus();
#ifdef ENABLE_BINPACKING
	for(i=0;i<max_proc;i++) {
		if (per_cpu(cosched_flagtime, i))
			myprintk("WARN! cosched value was not cleared yet??\n");
		per_cpu(cosched_flagtime, i) = 0;
		per_cpu(cosched_expected, i) = 0;
	}
#endif
	for(i=0;i<max_proc;i++) {
		if (per_cpu(locked_pt, i))
			myprintk("lingering locked_pt at P%d\n", i);
		per_cpu(locked_pt, i) = 0;

		per_cpu(locked_pt_loc, i) = 0;

		if (per_cpu(found_pt, i))
			myprintk("lingering found_pt at P%d\n", i);
		per_cpu(found_pt, i) = 0;
		if (i==0)
			myprint_cpu_info(&cpu_data[i]);
	}
#ifdef ENABLE_TIMESTAMP
	for(i=0;i<max_proc;i++) {
		init_timestamp(&per_cpu(timestamp, i));
	}
#endif
#ifdef ENABLE_CACHE_BALANCE
	spin_lock_init(&migrating_lock);
#endif
	spin_lock_init(&temp_lock);
#ifdef DEBUG_HISTOGRAM	// for debugging
	spin_lock_init(&hist_lock);
#endif
	if (mini_disabling)
		mypanic("mini_disabling is set?");

	memset(pcount, 0, sizeof(pcount));
/*	for(i=0;i<COUNT_MAX;i++)
		pcount[i] = 0;*/

	print_config();
	compute_bits_in_char ();
#ifdef ENABLE_PTMAN
	init_ptman();
#endif
#ifdef ENABLE_CACHEMAN1
	init_cacheman();
#endif
#ifdef ENABLE_DENSITY
	// should be fine
	memset(abit_density_shared, 0, sizeof(abit_density_shared));
#endif

	long cpus = (long)num_online_cpus();

#ifdef ENABLE_ASYMMETRIC_CACHE
	if (cpus != max_proc-1) {
		myprintk("WARN! enabling cancelled...#PCPU=%d (need %d)\n", cpus, max_proc-1);
		return 1;
	}
#else
	if (cpus != max_proc) {	// make sure we have all PCPUs
		myprintk("WARN! enabling cancelled...#PCPU=%d (need %d)\n", cpus, max_proc);
		return 1;
	}
#endif
	if (!mytable) {	// if allocation failed.
		myprintk("null mytable. cancel enableing\n");
		return 1;
	}


	for(i=0;i<max_page;i++) {
#ifdef ENABLE_ABIT
		FTABLE_ABIT(i) = 0;
		FTABLE_TIME(i) = 0;
#endif
	}


#ifdef VERBOSE_PAGE_FAULT
//	pf_count = 100;
#endif
	mini_activated = 1;
	on_each_cpu(_enable_soft_cache, NULL, 1);	// smp.h
	return 0;
}

#define MYARRAY_SIZE2	32
void printx_each_vcpu(void)
{
	struct vcpu *v;
	struct domain *d;
	unsigned long array[MYARRAY_SIZE2];
	int no;

	int i;
	for(i=0;i<12;i++)
		array[i] = 12-i;
	MYXTRACE(TRC_MIN_EACH_VCPU, 12, array);

#if 0
	rcu_read_lock(&domlist_read_lock);
	for_each_domain_vcpu(d, v) {
		array[0] = d->domain_id;
		array[1] = v->vcpu_id;
		array[2] = v->ptouch_count[0];
		array[3] = v->ptouch_count[1];
		array[4] = v->ptouch_count[2];
		array[5] = v->ptouch_count[3];
		array[6] = v->ptouch_count[4];
		array[7] = 0;
		array[8] = 0;
		array[9] = 0;
		array[10] = 0;
		array[11] = 0;
//		array[11] = counter[COUNT_VR_MIGRATION];	// TODO: this is not per-vcpu
int csched_info(struct vcpu *v, unsigned long array[]);
#ifdef ENABLE_BINPACKING
#error TODO
		no = csched_info(v, &array[12]);	// puts scheduler info
#else
		no = 0;
#endif
		MYXTRACE(TRC_MIN_EACH_VCPU, 12+no, array);
		if (12+no >= MYARRAY_SIZE2)
			panic("SIZE2\n");
	}
	rcu_read_unlock(&domlist_read_lock);
#endif
}

#ifdef DEBUG_STAT
void print_each_vcpu(void)
{
	struct vcpu *v;
	struct domain *d;
	unsigned long array[12];
	rcu_read_lock(&domlist_read_lock);
	for_each_domain_vcpu(d, v) {
		array[0] = d->domain_id;
		array[1] = v->vcpu_id;
		array[2] = v->vcount[0];
		array[3] = v->vcount[1];
		array[4] = v->vcount[2];
		array[5] = v->vcount[3];
		array[6] = v->vcount[4];
		array[7] = 0;
		array[8] = 0;
		array[9] = 0;
		array[10] = 0;
		array[11] = 0;
//		array[11] = counter[COUNT_VR_MIGRATION];	// TODO this is not per-vcpu
		myprintk("d%dv%d, ptouch:%d=~%d+%d,%d,%d u-sched:%d/%d,%d loop-detect:%d\n", array[0], array[1], array[2], array[3], array[4], array[5], array[6], array[7], array[8], array[9], array[10]);
	}
	rcu_read_unlock(&domlist_read_lock);
}
#endif

int usched_print;

void heartbeat(void)
{
	static int prev[COUNT_MAX];
	myprintk(
		"pt(%d,%d) sys:%d usched:%d gl:%d "
//		"tm:%d ir:%d api:%d "
		"ab:%d\t"
		"$(%d %d) core(%d %d) "
#ifdef ENABLE_HOT_PAGES
		"listcnt: %d "
		"hot:%d (%d,%d,%d,%d) "
#endif
#ifdef ENABLE_HETERO
		"het:%d (%d/%d,%d/%d,%d/%d,%d/%d)\t"
//"(%d,%d,%d,%d)\t"
#endif
#ifdef ENABLE_MYPROF
		"samples:%d\t"
#endif
		"\n"
		, pcount[COUNT_PAGE_TOUCH_USER]-prev[COUNT_PAGE_TOUCH_USER]
		, pcount[COUNT_PAGE_TOUCH_KERNEL]-prev[COUNT_PAGE_TOUCH_KERNEL]
		, pcount[COUNT_SYSCALL]-prev[COUNT_SYSCALL]
		, pcount[COUNT_USCHED]-prev[COUNT_USCHED]
		, pcount[COUNT_GLOBALIZE]-prev[COUNT_GLOBALIZE]
//		, pcount[COUNT_TOGGLE_MODE]-prev[COUNT_TOGGLE_MODE]
//		, pcount[COUNT_IRET]-prev[COUNT_IRET]
//		, pcount[COUNT_GUEST_API]-prev[COUNT_GUEST_API]
		, pcount[COUNT_CLEAR_ABIT]-prev[COUNT_CLEAR_ABIT]
		, ACTIVE_FRAMES_CACHE(0), ACTIVE_FRAMES_CACHE(1)
#ifdef ENABLE_MEASURE_UNBALANCE
		, atomic_read(&cacheman[0].vcpu_count), atomic_read(&cacheman[1].vcpu_count)
#else
		, 0, 0
#endif
#ifdef ENABLE_HOT_PAGES
		, hetero_hotpg_cnt
		, seed_user_hot->frame_count
		, atomic_read(&hot_pages_vm[0])
		, atomic_read(&hot_pages_vm[1])
		, atomic_read(&hot_pages_vm[2])
		, atomic_read(&hot_pages_vm[3])
#endif
#ifdef ENABLE_HETERO
		, atomic_read(&hetero_pages_count)
		, atomic_read(&hetero_pages_vm[0]), hetero_pages_vm_limit[0]
		, atomic_read(&hetero_pages_vm[1]), hetero_pages_vm_limit[1]
		, atomic_read(&hetero_pages_vm[2]), hetero_pages_vm_limit[2]
		, atomic_read(&hetero_pages_vm[3]), hetero_pages_vm_limit[3]
/*		, vm_tot_pages[0]
		, vm_tot_pages[1]
		, vm_tot_pages[2]
		, vm_tot_pages[3]*/
#endif
#ifdef ENABLE_MYPROF
		, my_total_samples
#endif
	);
#if 0 // def DEBUG_WARN
	int diff = pcount[COUNT_SYSCALL]-pcount[COUNT_SYSRET];
	if (diff > max_proc || diff < -max_proc) {
		myprintk("WARN: syscall:%d, sysret:%d\n", pcount[COUNT_SYSCALL], pcount[COUNT_SYSRET]);
	}
#endif
//	print_cache(1);

#ifdef ENABLE_MYPROF
	my_total_samples = 0;
#endif
	memcpy(prev, pcount, sizeof(pcount));
}

void printx_cache(int verbose)
{
	int i,j;
	struct page_dir *pgd;
	int pgd_count[MAX_CACHE];
	int pgd_count_total = 0;
	for(i=0;i<MAX_CACHE;i++)
		pgd_count[i] = 0;
#if 0
	myspin_lock(&pgd_list_lock, 39);
	list_for_each_entry(pgd, &pgd_list, list) {
		// TODO pgd_count[pgd->current_cache]++;
	}
	spin_unlock(&pgd_list_lock);
#endif
#if 0 // TODO
	for(i=0;i<MAX_CACHE;i++) {
		TRACE_5D(TRC_MIN_CACHE, i, cacheman[i].size/4 , cacheman[i].frames_count, cacheman[i].vregions_count, pgd_count[i] );
		pgd_count_total += pgd_count[i];
#ifdef ENABLE_DENSITY
		unsigned long array[34];
		for(j=0;j<32;j++)
			array[j] = cacheman[i].abit_density[j];
		array[32] = ACTIVE_FRAMES_CACHE(i);
		array[33] = i;
		MYXTRACE(TRC_MIN_CACHE_DENSITY, 34, array);
#endif
#ifdef ENABLE_DENSITY
		myspin_lock(&pgd_list_lock, 131);
		list_for_each_entry(pgd, &pgd_list, list) {
			if (ACTIVE_FRAMES_PGD(pgd, i)) {
				array[33] = pgd->mfn;
				for(j=0;j<32;j++)
					array[j] = atomic_read(&pgd->abit_density[i][j]);
				array[32] = ACTIVE_FRAMES_PGD(pgd, i);
				MYXTRACE(TRC_MIN_PGD_DENSITY, 34, array);
			}
		}
		spin_unlock(&pgd_list_lock);
		for(j=0;j<32;j++)
			array[j] = atomic_read(&abit_density_shared[i][j]);
		array[33] = 0;
		array[32] = ACTIVE_FRAMES_SHARED(i);
		MYXTRACE(TRC_MIN_SHARED_DENSITY, 34, array);
#endif
		printx_each_cache(i, verbose);
	}
	TRACE_1D(TRC_MIN_CACHE_PGD_COUNT, pgd_count_total);
#endif
}

#ifdef ENABLE_GLOBAL_LIST
void print_vregions_seed(int flag, int *count)
{
#ifdef ENABLE_VREGIONS
	struct vregion_t *vr, *temp;
	struct vregion_t temp_vr;
	temp = &temp_vr;
	temp->flags = ~0UL;

//	int max = 100;
	int skip_count = 0;
	myspin_lock(&vregions_seed_lock, 173);
	list_for_each_entry(vr, &vregions_seed, global_list) {
		count[1]++;
		count[2] += vr->frame_count;
		count[3] += vr->rmap_count[0];
		count[4] += vr->rmap_count[1];	// TODO: generalize
/*
		if (cachemap_is_global(vr) && vr->frame_count==1) {
			count[0]++;
			continue;
		}
*/
//		if (max) {
			if (vr->flags == temp->flags && vr->frame_count == temp->frame_count &&
				vr->rmap_count[0] == temp->rmap_count[0] &&
				vr->rmap_count[1] == temp->rmap_count[1]) {
				skip_count++;
			} else {
				if (skip_count) {
					myprintk("%d skipped.\n", skip_count);
					skip_count = 0;
				}
				print_vregion(vr, flag);
				*temp = *vr;
			}
/*			if (--max == 0) {
				if (skip_count) {
					myprintk("%d skipped.\n", skip_count);
					skip_count = 0;
				}
				myprintk(".. skip 0 or more regions ...\n");
			}*/
//		}
	}
	spin_unlock(&vregions_seed_lock);
	if (skip_count) {
		myprintk("%d skipped.\n", skip_count);
		skip_count = 0;
	}
	return;
#endif
}

void print_all_vregions(void)
{
	int count[5];
	memset(count, 0, sizeof(count));
	myprintk(" ---- seed regions ----\n");
	print_vregions_seed(0, count);
	myprintk("..and %d 1-paged global, so %dvr %dframe %d,%d rmap\n", count[0], count[1], count[2], count[3], count[4]);
}
#else
void print_all_vregions(void) {}
#endif

void print_openbit_count(struct page_dir *pgd)
{
	int i;
	MYASSERT(pgd);
	printk("stat:");
	for(i=0;i<max_cache;i++) {
		printk("%3d,", pgd->openbit_count[i]);
	}
	printk("/%d", pgd->mark_count);
}

void print_pgd(struct page_dir *pgd, int flag)
{
	myprintk("pgd:%x(mfn:%5x,%5x)f:%x "
#if 0
			"comm:%s "
#endif
			, pgd, pgd->pt->mfn, pgd->mfn_user, pgd->flag
#if 0
			, get_comm(pgd->current_kstack)
#endif
			);
	print_openbit_count(pgd);
	printk("\n");
}

void print_pgds(int verbose)
{
#ifdef ENABLE_PGD
	struct page_dir *pgd;
	myprintk("-- pgd reports --\n");
	myspin_lock(&pgd_list_lock, 39);
	list_for_each_entry(pgd, &pgd_list, list) {
		print_pgd(pgd,0);
	}
	spin_unlock(&pgd_list_lock);
#endif
}


void _disable_soft_cache(void *info)
{
	int cpu = smp_processor_id();
//	myprintk("CPU%d: disabled\n", cpu);
}

unsigned long disable_soft_cache(void)
{
	unsigned long ret = 0;
	int i;
	if (!mini_activated) {
		myprintk("already disabled\n");
		return ret;
	}
	if (mini_disabling)
		mypanic("NO ! mini_disabling");
	mini_disabling = 1;
	mini_activated = 0;

	int value;
	if (value = atomic_read(&mini_count)) {
		myprintk("Waiting mini_count = %d...", value);
#if 1
		for(i=0;i<MAX_PLACE;i++)
			printk("%d, ", atomic_read(&mini_place[i]));
#endif
		printk("\n");
		while(atomic_read(&mini_count)) {
			cpu_relax();
		}
	}

	myprintk("==================== DISABLED ======================\n");
	on_each_cpu(_disable_soft_cache, NULL, 1);	// smp.h
#ifdef ENABLE_TRACK_MEMLEAK
//	memleak_report();	// print current xenheap usage
#endif
#ifdef ENABLE_TRACK_SPINLOCK
	spinlock_report();
#endif
//	print_cache(0);
#ifdef ENABLE_PGD
	del_all_pgd();
#endif
	struct vcpu *v;
	struct domain *d;
	mini_disabling = 0;

#ifdef ENABLE_GLOBAL_LIST
	myspin_lock(&vregions_seed_lock, 106);
        if (!list_empty(&vregions_seed)) {
                myprintk("WARN !!!! : still have some vregions_seed??\n");
        }
	spin_unlock(&vregions_seed_lock);
#endif
#ifdef DEBUG_STAT
	print_each_vcpu();
//	print_vr_flags(0);
//	print_vr_flags(1);
#endif
	myprintk("after cleaned up\n");
	print_pgds(1);
	print_all_vregions();
//	print_cache(1);
#ifdef ENABLE_TIMESTAMP
	print_timestamp();
#endif
#ifdef ENABLE_CACHEMAN1
	check_cacheman_after_cleanup();
#endif

#ifdef ENABLE_VREGIONS
	check_vrt();
#endif

/*	// TODO: move this to shutdown..
	if (mytable && mytable != -1)
		myxfree(mytable, 5);
*/
#ifdef ENABLE_VREGIONS
	myprintk("vregions_free_count:%d vs original:%d\n", vregions_free_count, num_vregions_per_1mb*vregion_1mb_pool_count);
	if (vregions_xmalloc_count)
		myprintk("WARN! Due to empty vregions_free,called xmalloc %d times. Increase pool size!\n", vregions_xmalloc_count);
#endif

	int j;
	// TODO: move this to sched_destroy_vcpu() function.. see sched_init_vcpu()
	rcu_read_lock(&domlist_read_lock);
	for_each_domain_vcpu(d,v) {
		cpumask_t temp_cpumask;
#ifdef DEBUG_STAT
		for(j=0;j<PTOUCH_MAX;j++)
			v->vcount[j] = 0;
#endif
#ifdef ENABLE_PGD
		v->current_pgd = NULL;
		v->current_kstack = NULL;
#endif
		v->dest_cache = -1;
		v->print_countdown = 0;
	}
	for_each_domain(d) {
		d->kernel_pgd = NULL;
		spin_lock_init(&d->kernel_pgd_lock);
	}
	rcu_read_unlock(&domlist_read_lock);
#ifdef ENABLE_HETERO
	if (atomic_read(&hetero_pages_count) != 0) {
		myprintk("WARNING! non-zero hetero_pages_count = %d\n", atomic_read(&hetero_pages_count));
	}
#endif
#ifdef ENABLE_TRACK_MEMLEAK
	memleak_report();	// should be all zero.. detecting memleak
	myprint_xenheap();
#endif

	return 0;
}



unsigned long do_myhypercall(unsigned long service, unsigned long parm2, unsigned long parm3, unsigned long parm4, unsigned long parm5)
{
	unsigned long ret = 0;

//	myprintk("service:0x%lx, parm2:0x%lx, parm3:0x%lx, parm4:0x%lx, parm5:0x%lx MAX_ORDER:%d\n", service, parm2, parm3, parm4, parm5, MAX_ORDER);

	if (service == 0x0 || service == 0x1) {
		if (!mini_activated)
			ret = enable_soft_cache();
		else
			ret = disable_soft_cache();
	} else if (service == 0x2) {
		myprintk("service=%d not defined!\n", service);
	} else if (service == 0x3) {
		// old myrecord() stuff
		myprintk("service=%d not defined!\n", service);
	} else if (service == 0x4) {
		// old myrecord() stuff
		myprintk("service=%d not defined!\n", service);
	} else if (service == 0x5) {
#ifdef ENABLE_RANGE
		if (current->current_pgd) {
			int rd = add_guest_region(parm2, 1);
			if (rd) {
				ret = add_range(current->current_pgd, parm2, parm3, rd);
				struct vregion_t *newvr = grt[rd].vr;
				construct_range_vr(parm2, parm3, newvr, rd);
	//			print_vregion(newvr, 0);
			}
		} else
			myprintk("WARN ignore add_range\n");
#else
		myprintk("ENABLE_RANGE required!\n");
#endif
	} else if (service == 0x6) {
#ifdef ENABLE_RANGE
		if (current->current_pgd) {
			int rd = del_range(current->current_pgd, parm2, parm3);
			del_guest_region(rd, 1);
		} else
			myprintk("WARN ignore del_range\n");
#else
		myprintk("ENABLE_RANGE required!\n");
#endif
	} else if (service == 0x7) {
/*
		if (!mini_activated) {
			myprintk("Not activated");
			return;
		}
		do_balance(3);
*/
	} else if (service == 0x8) {
#ifdef ENABLE_RANGE
#ifdef ENABLE_VREGION_MAPPING
		if (current->current_pgd) {
			struct vregion_t *vr;
			vr = grt[current->current_pgd->ranges[parm2].rd].vr;	// TODO: refcnt?
			MYASSERT(vr>= HYPERVISOR_VIRT_START);
			myprintk("[%d] vr %p : close cache(%d)\n", parm2, vr, parm3);
print_vregion(vr, 0);
			if (parm3 >= 0 && parm3 < MAX_CACHE) {
				myspin_lock(&vr->lock, 106);
				if (is_vregion_cache_mapped(vr, parm3)) {
					close_vregion_cache(vr, parm3);
				} else {
					myprintk("skip: already closed vr!\n");
				}
				spin_unlock(&vr->lock);
			} else
				myprintk("Invalid cache %d\n", parm3);
		} else
			myprintk("WARN ignore ops_range\n");
#else
		myprintk("ENABLE_VREGION_MAPPING required!\n");
#endif
#else
		myprintk("ENABLE_RANGE required!\n");
#endif
#ifdef ENABLE_GUEST_REGION
	} else if (service == 0xa) {
		ret = add_guest_region(parm2, 0);
		pcount[COUNT_GUEST_API]++;
	} else if (service == 0xb) {
		del_guest_region(parm2, 1, current->domain);
		ret = parm2;	// returns the given rd
		pcount[COUNT_GUEST_API]++;
	} else if (service == 0xc) {
/*		// debug code.. sometimes mfn == -1, so let's just use parm2
		unsigned long mfn;
		mfn = (read_cr3() >> PAGE_SHIFT);
		mfn = my_table_walk(parm5, mfn, 0);
		if (mfn != parm2)
			myprintk("[addr:%p mfn:%lx != parm2:%lx] ", parm5, mfn, parm2);
		if (mfn != -1)
			add_page_guest_region(mfn, parm3, parm4);
		else {
			myprintk("WARN!!! mfn == -1, use given mfn %lx instead..add..\n", parm2);
			add_page_guest_region(parm2, parm3, parm4);
		}
*/
		MYASSERT(maddr_get_owner(parm2 << PAGE_SHIFT) == current->domain);
		add_page_guest_region(parm2, 0/*TODO*/, parm4);
		pcount[COUNT_GUEST_API]++;
	} else if (service == 0xd) {
/*		// debug code.. sometimes mfn == -1, so let's just use parm2
		unsigned long mfn;
		mfn = (read_cr3() >> PAGE_SHIFT);
		mfn = my_table_walk(parm5, mfn, 0);
		if (mfn != parm2)
			myprintk("[addr:%p mfn:%lx != parm2:%lx] ", parm5, mfn, parm2);
		if (mfn != -1)
			del_page_guest_region(mfn, parm3, parm4);
		else {
			myprintk("WARN!!! mfn == -1, use given mfn %lx instead..del..\n", parm2);
			del_page_guest_region(parm2, parm3, parm4);
		}
*/
		MYASSERT(maddr_get_owner(parm2 << PAGE_SHIFT) == current->domain);
		del_page_guest_region(parm2, 0/*TODO*/, parm4);
		pcount[COUNT_GUEST_API]++;
#endif
	} else if (service == 0xe) { // vishal's use
		if( parm2 == 1){ //ENABLE_PERFMON
				enable_perfmon = parm3;
		}

	} else {
//		myprintk("service=%ld not defined!\n", service);
	}
	return ret;
}
