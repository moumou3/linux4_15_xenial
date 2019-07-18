#ifndef __LINUX_EXPR_H
#define __LINUX_EXPR_H

#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/sched.h>


int expr_madvise(struct vm_area_struct *vma, unsigned long start,
                        unsigned long end, int advice, unsigned long *vm_flags);
int __expr_enter(struct mm_struct *mm);
void __expr_exit(struct mm_struct *mm);

#endif /* __LINUX_KSM_H */
