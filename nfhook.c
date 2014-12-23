#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jagadeesh");

static int nfhook_init(void)
{
	return 0;	
}

static void nfhook_exit(void)
{
	
}

module_init(nfhook_init);
module_exit(nfhook_exit);
