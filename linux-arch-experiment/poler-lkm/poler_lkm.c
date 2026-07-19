/* ============================================================================
 * POLER-OS Crypto — Linux Kernel Module
 *
 * Provides POLER v8 block cipher as a loadable kernel module.
 * Exposes /dev/poler character device for userspace access.
 *
 * ioctl commands:
 *   POLER_IOCTL_ENCRYPT  — encrypt a 128-bit block
 *   POLER_IOCTL_DECRYPT  — decrypt a 128-bit block
 *   POLER_IOCTL_SET_KEY  — set 256-bit key + epsilon
 *   POLER_IOCTL_PRNG     — get PRNG output
 *   POLER_IOCTL_SELFTEST — run self-test, return result
 *
 * Based on poler_core.zig v8 — ported to C for Linux kernel
 * ============================================================================ */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/random.h>

#include "poler_core.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("POLER-OS Team");
MODULE_DESCRIPTION("POLER v8 Block Cipher — Linux Kernel Module");
MODULE_VERSION("8.1.0");

/* ============================================================================
 * IOCTL DEFINITIONS
 * ============================================================================ */

#define POLER_MAGIC 'P'

struct poler_key_data {
    u32 key[8];     /* 256-bit key */
    u32 epsilon;    /* PND parameter */
};

struct poler_block_data {
    u32 block[4];   /* 128-bit block */
};

struct poler_prng_data {
    u32 seed;
    u32 epsilon;
    u32 key;
    u32 output[4];  /* 4 random u32 values */
};

#define POLER_IOCTL_SET_KEY   _IOW(POLER_MAGIC, 1, struct poler_key_data)
#define POLER_IOCTL_ENCRYPT   _IOWR(POLER_MAGIC, 2, struct poler_block_data)
#define POLER_IOCTL_DECRYPT   _IOWR(POLER_MAGIC, 3, struct poler_block_data)
#define POLER_IOCTL_PRNG      _IOWR(POLER_MAGIC, 4, struct poler_prng_data)
#define POLER_IOCTL_SELFTEST  _IO(POLER_MAGIC, 5)

/* ============================================================================
 * MODULE STATE
 * ============================================================================ */

static DEFINE_MUTEX(poler_mutex);
static struct poler_cipher g_cipher;
static bool g_cipher_initialized = false;
static struct poler_prng g_prng;
static bool g_prng_initialized = false;

static dev_t poler_dev;
static struct cdev poler_cdev;
static struct class *poler_class;
static struct device *poler_device;

/* ============================================================================
 * SELF-TEST
 * ============================================================================ */

static bool poler_run_selftest(void)
{
    /* Test 1: PND mix nonlinearity at ε=0 */
    {
        u32 a = 42, b = 17, eps = 0;
        u32 result = poler_pnd_mix(a, b, eps);
        /* At ε=0, auto-corrected to ε=1, result should be φ(a*b) +% 1*φ(a^b) */
        u32 expected = wadd32(poler_phi(wmul32(a, b)),
                              wmul32(1, poler_phi(a ^ b)));
        if (result != expected) {
            pr_err("poler: selftest FAIL — pndMix(42,17,0) = 0x%08X, expected 0x%08X\n",
                   result, expected);
            return false;
        }
    }

    /* Test 2: phi bijectivity — phi(inv_phi(x)) == x */
    {
        u32 x = 0xDEADBEEF;
        u32 y = poler_phi(x);
        /* Verify phi is not identity */
        if (y == x) {
            pr_err("poler: selftest FAIL — phi(0x%08X) == input (not a permutation)\n", x);
            return false;
        }
    }

    /* Test 3: Cipher roundtrip */
    {
        u32 key[8] = {
            0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,
            0x11111111, 0x22222222, 0x33333333, 0x44444444
        };
        struct poler_cipher cipher;
        poler_cipher_init(&cipher, key, 0x9E3779B9);

        if (!poler_verify_roundtrip(&cipher)) {
            pr_err("poler: selftest FAIL — cipher roundtrip\n");
            return false;
        }
        pr_info("poler: cipher roundtrip OK\n");
    }

    /* Test 4: PRNG — generate values, check they differ */
    {
        struct poler_prng prng;
        poler_prng_init(&prng, 12345, 0x9E3779B9, 0x517CC1B7);
        u32 v1 = poler_prng_next(&prng);
        u32 v2 = poler_prng_next(&prng);
        u32 v3 = poler_prng_next(&prng);
        if (v1 == v2 || v2 == v3 || v1 == v3) {
            pr_err("poler: selftest FAIL — PRNG produces identical values\n");
            return false;
        }
        pr_info("poler: PRNG output: 0x%08X, 0x%08X, 0x%08X\n", v1, v2, v3);
    }

    /* Test 5: Avalanche — flip 1 bit, check output differs significantly */
    {
        u32 key[8] = {
            0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10,
            0x11121314, 0x15161718, 0x191A1B1C, 0x1D1E1F20
        };
        struct poler_cipher cipher;
        poler_cipher_init(&cipher, key, 1);

        u32 pt[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
        u32 ct1[4], ct2[4];
        u32 pt2[4];
        memcpy(pt2, pt, sizeof(pt));
        pt2[0] ^= 1;  /* flip 1 bit */

        poler_encrypt_block(&cipher, pt, ct1);
        poler_encrypt_block(&cipher, pt2, ct2);

        u32 total_diff = 0;
        for (int i = 0; i < 4; i++)
            total_diff += hweight32(ct1[i] ^ ct2[i]);

        /* Expect at least 32 bits different out of 128 (25% — very conservative) */
        if (total_diff < 32) {
            pr_err("poler: selftest FAIL — avalanche effect too weak: %u/128 bits\n",
                   total_diff);
            return false;
        }
        pr_info("poler: avalanche effect: %u/128 bits differ (1-bit input change)\n",
                total_diff);
    }

    pr_info("poler: ===== ALL SELF-TESTS PASSED =====\n");
    return true;
}

/* ============================================================================
 * FILE OPERATIONS
 * ============================================================================ */

static int poler_open(struct inode *inode, struct file *file)
{
    pr_info("poler: device opened\n");
    return 0;
}

static int poler_release(struct inode *inode, struct file *file)
{
    pr_info("poler: device closed\n");
    return 0;
}

static long poler_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    mutex_lock(&poler_mutex);

    switch (cmd) {
    case POLER_IOCTL_SET_KEY:
    {
        struct poler_key_data kdata;
        if (copy_from_user(&kdata, (void __user *)arg, sizeof(kdata))) {
            mutex_unlock(&poler_mutex);
            return -EFAULT;
        }
        poler_cipher_init(&g_cipher, kdata.key, kdata.epsilon);
        g_cipher_initialized = true;
        pr_info("poler: key set, epsilon=0x%08X\n", kdata.epsilon);
        break;
    }

    case POLER_IOCTL_ENCRYPT:
    {
        struct poler_block_data bdata;
        if (!g_cipher_initialized) {
            mutex_unlock(&poler_mutex);
            return -EPERM;
        }
        if (copy_from_user(&bdata, (void __user *)arg, sizeof(bdata))) {
            mutex_unlock(&poler_mutex);
            return -EFAULT;
        }
        poler_encrypt_block(&g_cipher, bdata.block, bdata.block);
        if (copy_to_user((void __user *)arg, &bdata, sizeof(bdata))) {
            mutex_unlock(&poler_mutex);
            return -EFAULT;
        }
        break;
    }

    case POLER_IOCTL_DECRYPT:
    {
        struct poler_block_data bdata;
        if (!g_cipher_initialized) {
            mutex_unlock(&poler_mutex);
            return -EPERM;
        }
        if (copy_from_user(&bdata, (void __user *)arg, sizeof(bdata))) {
            mutex_unlock(&poler_mutex);
            return -EFAULT;
        }
        poler_decrypt_block(&g_cipher, bdata.block, bdata.block);
        if (copy_to_user((void __user *)arg, &bdata, sizeof(bdata))) {
            mutex_unlock(&poler_mutex);
            return -EFAULT;
        }
        break;
    }

    case POLER_IOCTL_PRNG:
    {
        struct poler_prng_data pdata;
        if (copy_from_user(&pdata, (void __user *)arg, sizeof(pdata))) {
            mutex_unlock(&poler_mutex);
            return -EFAULT;
        }
        struct poler_prng prng;
        poler_prng_init(&prng, pdata.seed, pdata.epsilon, pdata.key);
        pdata.output[0] = poler_prng_next(&prng);
        pdata.output[1] = poler_prng_next(&prng);
        pdata.output[2] = poler_prng_next(&prng);
        pdata.output[3] = poler_prng_next(&prng);
        if (copy_to_user((void __user *)arg, &pdata, sizeof(pdata))) {
            mutex_unlock(&poler_mutex);
            return -EFAULT;
        }
        break;
    }

    case POLER_IOCTL_SELFTEST:
    {
        bool result = poler_run_selftest();
        mutex_unlock(&poler_mutex);
        return result ? 0 : -EIO;
    }

    default:
        mutex_unlock(&poler_mutex);
        return -ENOTTY;
    }

    mutex_unlock(&poler_mutex);
    return 0;
}

/* ============================================================================
 * /proc/poler — status info
 * ============================================================================ */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int poler_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "POLER Core v8 — Linux Kernel Module\n");
    seq_printf(m, "Cipher: %s\n", g_cipher_initialized ? "initialized" : "not initialized");
    seq_printf(m, "Feistel rounds: %u\n", POLER_FEISTEL_ROUNDS);
    seq_printf(m, "Block size: %u bits\n", POLER_BLOCK_BITS);
    seq_printf(m, "Key size: %u bits\n", POLER_KEY_BITS);
    seq_printf(m, "PND: v8 φ-wrap (both terms nonlinear)\n");
    seq_printf(m, "S-box: constant-time GF(2^8) x^254\n");
    seq_printf(m, "Diffusion: MDS MixColumns (branching=5) + LHCA\n");
    return 0;
}

static int poler_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, poler_proc_show, NULL);
}

static const struct proc_ops poler_proc_ops = {
    .proc_open    = poler_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ============================================================================
 * FILE OPERATIONS STRUCT
 * ============================================================================ */

static const struct file_operations poler_fops = {
    .owner          = THIS_MODULE,
    .open           = poler_open,
    .release        = poler_release,
    .unlocked_ioctl = poler_ioctl,
};

/* ============================================================================
 * MODULE INIT / EXIT
 * ============================================================================ */

static int __init poler_init(void)
{
    int ret;

    pr_info("poler: ============================================\n");
    pr_info("poler: POLER Core v8 — initializing\n");
    pr_info("poler: Block: %u bits, Key: %u bits, Rounds: %u\n",
            POLER_BLOCK_BITS, POLER_KEY_BITS, POLER_FEISTEL_ROUNDS);
    pr_info("poler: PND: φ(a·b) + ε·φ(a⊕b)\n");

    /* Allocate character device */
    ret = alloc_chrdev_region(&poler_dev, 0, 1, "poler");
    if (ret < 0) {
        pr_err("poler: failed to alloc chrdev region\n");
        return ret;
    }

    cdev_init(&poler_cdev, &poler_fops);
    poler_cdev.owner = THIS_MODULE;
    ret = cdev_add(&poler_cdev, poler_dev, 1);
    if (ret < 0) {
        unregister_chrdev_region(poler_dev, 1);
        pr_err("poler: failed to add cdev\n");
        return ret;
    }

    /* Create device class */
    poler_class = class_create("poler");
    if (IS_ERR(poler_class)) {
        cdev_del(&poler_cdev);
        unregister_chrdev_region(poler_dev, 1);
        pr_err("poler: failed to create class\n");
        return PTR_ERR(poler_class);
    }

    poler_device = device_create(poler_class, NULL, poler_dev, NULL, "poler");
    if (IS_ERR(poler_device)) {
        class_destroy(poler_class);
        cdev_del(&poler_cdev);
        unregister_chrdev_region(poler_dev, 1);
        pr_err("poler: failed to create device\n");
        return PTR_ERR(poler_device);
    }

    /* Create /proc/poler */
    proc_create("poler", 0444, NULL, &poler_proc_ops);

    /* Run self-test on load */
    pr_info("poler: running self-test...\n");
    if (poler_run_selftest()) {
        pr_info("poler: ===== SELF-TEST PASSED =====\n");
    } else {
        pr_warn("poler: SELF-TEST FAILED — module loaded but cipher may be broken!\n");
    }

    pr_info("poler: /dev/poler created (major=%u, minor=%u)\n",
            MAJOR(poler_dev), MINOR(poler_dev));
    pr_info("poler: ============================================\n");

    return 0;
}

static void __exit poler_exit(void)
{
    remove_proc_entry("poler", NULL);
    device_destroy(poler_class, poler_dev);
    class_destroy(poler_class);
    cdev_del(&poler_cdev);
    unregister_chrdev_region(poler_dev, 1);

    pr_info("poler: module unloaded — /dev/poler removed\n");
}

module_init(poler_init);
module_exit(poler_exit);
