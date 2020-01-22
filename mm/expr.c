#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/hugetlb.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <asm/page.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/memory.h>
#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/hashtable.h>
#include <linux/freezer.h>
#include <linux/oom.h>
#include <linux/xxhash.h>
#include <linux/expr.h>

#include <linux/time.h>
#include <asm/tlbflush.h>
#include "internal.h"
#include "mytrace.h"

#define GPU_LAUNCH 0x1
#define GPU_CALCEND 0x2
#define ALLOC_PAGES 1

#define HUGE_SIZE 2 * 1024 * 1024

/*exugpud mm */
struct vm_area_struct *exugpud_vma;
EXPORT_SYMBOL(exugpud_vma);
struct vm_area_struct *hugeapp_vma;
unsigned int hugesize;
unsigned char *exugpud_flag = NULL;
EXPORT_SYMBOL(exugpud_flag);
static unsigned int *exugpud_out;
static unsigned int *mapped_pagenum = NULL;
static int run_flag = 0;

// wait queue
static DECLARE_WAIT_QUEUE_HEAD(expr_thread_wait);
static DEFINE_MUTEX(expr_thread_mutex);

//rdtsc variable
unsigned long long allexpr_start, allexpr_end, allexpr_sub;
unsigned long long flush_start, flush_end, flush_sub;
unsigned long long remap_start, remap_end, remap_sub;
unsigned long long daemon_start, daemon_end, daemon_sub;
unsigned long long clear_start, clear_end, clear_sub;
unsigned long long memsettest_start, memsettest_end, memsettest_sub;
unsigned long long remap_huge_start, remap_huge_end, remap_huge_sub;
struct timeval memset_tvstart, memset_tvend, memset_tvsub;

static inline void tvsub(struct timeval *x,
                         struct timeval *y,
                         struct timeval *ret)
{
  ret->tv_sec = x->tv_sec - y->tv_sec;
  ret->tv_usec = x->tv_usec - y->tv_usec;
  if (ret->tv_usec < 0) {
    ret->tv_sec--;
    ret->tv_usec += 1000000;
  }
}

int check_page_zero(struct page *page) {
  char *addr;
  int i;
  int flag = 1;

  addr = kmap_atomic(page);
  for (i = 0; i < PAGE_SIZE; ++i) {
    if (addr[i])
      flag = 0;
  }
  kunmap_atomic(addr); 
  return flag;

}

void memset_to_pages(struct page *pages, int pagenum) {

  char *addr;
  int i;
  for (i = 0; i < pagenum; ++i) {
    /*
    addr = kmap_atomic(&pages[i]);
    memset(addr,0x0, PAGE_SIZE); 
    kunmap_atomic(addr);
    */
    clear_page(&pages[i]);
  }

}

void exprfunc_print_rdtsc(void) {

  allexpr_sub = allexpr_end - allexpr_start; 
  flush_sub = flush_end - flush_start; 
  remap_sub = remap_end - remap_start; 
  daemon_sub = daemon_end - daemon_start; 
  clear_sub = clear_end - clear_start; 
  memsettest_sub = memsettest_end - memsettest_start; 
  tvsub(&memset_tvend, &memset_tvstart, &memset_tvsub);
  unsigned long tv_sub_usec = memset_tvsub.tv_sec * 1000000 + memset_tvsub.tv_usec;
  printk("allexpr: %llu\n", allexpr_sub);
  printk("flush: %llu\n", flush_sub);
  printk("remap: %llu\n", remap_sub);
  printk("daemon: %llu\n", daemon_sub);
  printk("clear: %llu\n", clear_sub);
  printk("memsettest: %llu\n", memsettest_sub);
  printk("memsettest_tv: %lu\n", tv_sub_usec);
}

pmd_t *my_huge_pte_offset(struct mm_struct *mm,
                       unsigned long addr)
{
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;

  pgd = pgd_offset(mm, addr);
  if (!pgd_present(*pgd))
    return NULL;
  p4d = p4d_offset(pgd, addr);
  if (!p4d_present(*p4d))
    return NULL;

  pud = pud_offset(p4d, addr);

  pmd = pmd_offset(pud, addr);

  /* hugepage or swap? */
  if (pmd_huge(*pmd) || !pmd_present(*pmd))
    return pmd;

  return NULL;
}

void huge_remap(void) 
{
  pte_t *ptep, entry;
  pmd_t *pmd1;
  pmd_t *pmd2;
  struct mm_struct *mm_ugpud = exugpud_vma->vm_mm;
  struct mm_struct *mm_hugeapp = hugeapp_vma->vm_mm;
  unsigned long gpud_address = exugpud_vma->vm_start;
  unsigned long long hugeapp_address = hugeapp_vma->vm_start;

  unsigned char* huge_ptr = (unsigned char*)hugeapp_address;

//  remap_huge_start = rdtsc(); //huge_start;

  pmd1 = my_huge_pte_offset(mm_hugeapp, hugeapp_address); //target hugeapp pmd
  pmd2 = my_huge_pte_offset(mm_ugpud, gpud_address); //gpu process pmd
  set_pmd_at(mm_ugpud, gpud_address, pmd2, *pmd1);

//  remap_huge_end = rdtsc(); //huge_end;

//  remap_huge_sub = remap_huge_end - remap_huge_start; 
//  printk("remap_huge: %llu\n", remap_huge_sub);



}

void expr_funcion_huge(void) {
  void* expr_memory;
  struct page *expr_pages;
  unsigned int expr_pagenum;
  int i;
  unsigned long long hugeapp_address;
  char* expr_addr;
  unsigned char *addr_head;
  size_t malloc_size;
  int pageorder;

  printk("expr_function_huge called\n");
    expr_pagenum = *mapped_pagenum;
  malloc_size = expr_pagenum * HUGE_SIZE;

  hugeapp_address = hugeapp_vma->vm_start;

     allexpr_start = rdtsc(); //allexpr_start
      remap_start = rdtsc(); //remap_start
  huge_remap();
      remap_end = rdtsc(); //remap_end
  *exugpud_flag = GPU_LAUNCH;

      daemon_start = rdtsc(); //daemon_start
  while(*exugpud_flag != GPU_CALCEND) {
    yield();
  }
      daemon_end = rdtsc(); //daemon_end;

      allexpr_end = rdtsc(); //allexpr_end


  exprfunc_print_rdtsc();
  printk("expr_funcion end\n");
}




void expr_funcion(void) {
  void* expr_memory;
  struct page *expr_pages;
  unsigned int expr_pagenum;
  int i;
  char* expr_addr;
  void *kmalloc_ptr;
  unsigned char *addr_head;
  size_t malloc_size;
  void *memset_test_ptr;
  int pageorder;

  printk("expr_function called");
  expr_pagenum = *mapped_pagenum;
  malloc_size = expr_pagenum * PAGE_SIZE;
  pageorder = get_order(malloc_size);
#ifdef ALLOC_PAGES
  expr_pages = alloc_pages(GFP_KERNEL, pageorder);
  /*
  memsettest_start = rdtsc(); //memsettest_start
  do_gettimeofday(&memset_tvstart);
  memset_to_pages(expr_pages, expr_pagenum);
  do_gettimeofday(&memset_tvend);
  memsettest_end = rdtsc(); //memsettest_end;
  exprfunc_print_rdtsc();
  */
#else

  if ((kmalloc_ptr = kmalloc(malloc_size + PAGE_SIZE, GFP_KERNEL)) == NULL) {
    MY_PRINT_DEBUG(malloc_size,0,0);
    return;
  }
  if ((memset_test_ptr = kmalloc(malloc_size + PAGE_SIZE, GFP_KERNEL)) == NULL) {
    MY_PRINT_DEBUG(malloc_size,0,0);
    return;
  }
  addr_head = (unsigned char*)((((unsigned long)kmalloc_ptr) + PAGE_SIZE - 1) & PAGE_MASK);
  memset(addr_head, 0x1, malloc_size);
//  memset(memset_test_ptr, 0x1, malloc_size);
#endif

  allexpr_start = rdtsc(); //allexpr_start
  *exugpud_flag = 0x0;
  flush_start = rdtsc(); //flush_start
  flush_cache_mm(exugpud_vma->vm_mm);
  flush_tlb_mm(exugpud_vma->vm_mm);
  flush_end = rdtsc(); //flush_end
  remap_start = rdtsc(); //remap_start
  for (i = 0; i < expr_pagenum; ++i) {
    struct page* tmp_page;
    unsigned long tmp_pfn;
#ifdef ALLOC_PAGES
    tmp_page = &expr_pages[expr_pagenum];
    tmp_pfn = page_to_pfn(tmp_page);
#else
    tmp_page = virt_to_page(addr_head + i * PAGE_SIZE);
    tmp_pfn = virt_to_phys(addr_head + i * PAGE_SIZE) >> PAGE_SHIFT;
#endif
    SetPageReserved(tmp_page);
    //remap_pfn_range(exugpud_vma, exugpud_vma->vm_start + i * PAGE_SIZE, virt_to_phys(addr_head + i * PAGE_SIZE) >> PAGE_SHIFT , PAGE_SIZE, exugpud_vma->vm_page_prot);
    remap_pfn_range(exugpud_vma, exugpud_vma->vm_start + i * PAGE_SIZE, tmp_pfn, PAGE_SIZE, exugpud_vma->vm_page_prot);
  }
  remap_end = rdtsc(); //remap_end
  *exugpud_flag = GPU_LAUNCH;

  daemon_start = rdtsc(); //daemon_start
  while(*exugpud_flag != GPU_CALCEND) {
    yield();
  }
  daemon_end = rdtsc(); //daemon_end;

  clear_start = rdtsc(); //clear_start
  for (i = 0; i < expr_pagenum; ++i) {
    struct page* tmp_page;
#ifdef ALLOC_PAGES
    tmp_page = &expr_pages[expr_pagenum];
#else
    tmp_page = virt_to_page(addr_head + i * PAGE_SIZE);
#endif
    ClearPageReserved(tmp_page);
  }
  clear_end = rdtsc(); //clear_end;
  allexpr_end = rdtsc(); //allexpr_end

#ifndef ALLOC_PAGES
  memsettest_start = rdtsc(); //memsettest_start
  memset(memset_test_ptr, 0x0, malloc_size);
  memsettest_end = rdtsc(); //memsettest_end;
#endif

  exprfunc_print_rdtsc();
#ifdef ALLOC_PAGES
  if (check_page_zero(expr_pages))
    printk("page zero ok");
  __free_pages(expr_pages, pageorder);
#else
  if(!addr_head[0])
    printk("page zero ok");
  kfree(kmalloc_ptr);
  kfree(memset_test_ptr);
#endif
  printk("expr_funcion end");
}

static int exprd_should_run(void)
{
  return run_flag;
}

int expr_scan_thread(void *nothing)
{
  set_freezable();
  set_user_nice(current, 5);

  printk("expr_scan_thread");
  while (!kthread_should_stop()) {
    mutex_lock(&expr_thread_mutex);
    if (exprd_should_run()) {
      expr_funcion_huge();
      run_flag = 0;
    }
    mutex_unlock(&expr_thread_mutex);

    try_to_freeze();

    if (exprd_should_run()) {
      //schedule_timeout_interruptible(
       // msecs_to_jiffies(ksm_thread_sleep_millisecs));
    } else {
      wait_event_freezable(expr_thread_wait,
                           exprd_should_run() || kthread_should_stop());
    }
  }
  return 0;
}



int expr_madvise(struct vm_area_struct *vma, unsigned long start,
                unsigned long end, int advice, unsigned long *vm_flags)
{
  struct mm_struct *mm = vma->vm_mm;
  int err;
  void *kmalloc_ptr;
  unsigned char *kmalloc_area;
  int i;
  unsigned long memsize;

  switch (advice) {
    case MADV_EXPR_INPUT:
      printk("input madvise start");
      exugpud_vma = vma;
      exugpud_vma->vm_flags |= VM_SHARED;
      *vm_flags |= VM_SHARED;
      printk("vma->start %llx", vma->vm_start);
      printk("start %llx", start);
      printk("vma->end %llx", vma->vm_end);
      printk("end %llx", end);
      if (is_cow_mapping(exugpud_vma->vm_flags))
        printk("cow_mapping");
      break;
    case MADV_EXPR_OUTPUT:
      memsize = end - start;
      printk("output madvise start");
      printk("vma->start %llx", vma->vm_start);
      printk("start %llx", start);
      printk("vma->end %llx", vma->vm_end);
      printk("end %llx", end);
      printk("exugpud_vma->start %llx", exugpud_vma->vm_start);
      printk("exugpud_vma->end %llx", exugpud_vma->vm_end);
      if (is_cow_mapping(exugpud_vma->vm_flags))
        printk("cow_mapping");

      if ((kmalloc_ptr = kmalloc(memsize + PAGE_SIZE, GFP_KERNEL)) == NULL) {
        MY_PRINT_DEBUG(0,0,0);
      }
      kmalloc_area = (unsigned char*)((((unsigned long)kmalloc_ptr) + PAGE_SIZE - 1) & PAGE_MASK);
      for (i = 0; i < memsize; i+= PAGE_SIZE) {
        SetPageReserved(virt_to_page(((unsigned long)kmalloc_area) + i));
      }
      exugpud_out = (unsigned int*)kmalloc_area;
      err = remap_pfn_range(vma, start, virt_to_phys((void *)kmalloc_area)>>PAGE_SHIFT, memsize, vma->vm_page_prot);
      break;
    case MADV_EXPR_FLAG:
      printk("flag madvise start");
      MY_PRINT_DEBUG(0,start,vma->vm_start);
      if ((kmalloc_ptr = kmalloc(2*PAGE_SIZE, GFP_KERNEL)) == NULL) {
        MY_PRINT_DEBUG(0,0,0);
      }
      kmalloc_area = (char*)((((unsigned long)kmalloc_ptr) + PAGE_SIZE - 1) & PAGE_MASK);
      for (i = 0; i < 1 * PAGE_SIZE; i+= PAGE_SIZE) {
        SetPageReserved(virt_to_page(((unsigned long)kmalloc_area) + i));
      }
      exugpud_flag = (unsigned char*)kmalloc_area;
      mapped_pagenum = (unsigned int*)(kmalloc_area + sizeof(unsigned char));
      *exugpud_flag = 0x0;
  printk("myhuge3 %lx, %lx\n", mapped_pagenum, virt_to_phys(mapped_pagenum));
      err = remap_pfn_range(vma, vma->vm_start, virt_to_phys((void *)kmalloc_area)>>PAGE_SHIFT, PAGE_SIZE, vma->vm_page_prot);
      break;
    case MADV_EXPR_RUN:
      printk("MADV_EXPR_RUN");
      hugeapp_vma = vma;
      hugesize = end - start;
      run_flag = 1;
      wake_up_interruptible(&expr_thread_wait);
  }

  return 0;
}



int __expr_enter(struct mm_struct *mm)
{
  printk("enter to expr");


  return 0;
}

void __expr_exit(struct mm_struct *mm)
{

  printk("exit expr");

}


static int __init expr_init(void)
{
  struct task_struct *expr_thread;
  int err = 0;

  expr_thread = kthread_run(expr_scan_thread, NULL, "expr");
  if (IS_ERR(expr_thread)) {
    pr_err("expr: creating kthread failed\n");
    err = PTR_ERR(expr_thread);
    goto out;
  }



  return 0;

out:
  return err;
}
subsys_initcall(expr_init);

