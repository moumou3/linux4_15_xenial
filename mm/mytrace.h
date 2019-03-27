#ifndef MYTRACE
#define MYTRACE
#include <linux/kernel.h>

#define MY_PRINT_DEBUG(arg1, arg2, arg3) \
       printk (KERN_DEBUG "[%s]: FUNC:%s: LINE:%d ARG1:%d ARG2:%lx ARG3:%lx \n", __FILE__, __FUNCTION__, __LINE__, arg1, arg2, arg3)


#endif
