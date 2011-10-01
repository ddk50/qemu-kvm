
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"

typedef struct diff2_header {
    char magic[32]; /* "Diff Virtual HD Image" */
    uint32_t version;
    uint32_t header_size;
    uint32_t sector;
    uint64_t total_size;
    uint64_t mom_sign;
    uint32_t cur_gen;
    uint64_t genmap_size;
    uint32_t bitmap_size;    
    uint32_t freezed; /* if 1, does not execute */
} Diff2Header;

typedef struct BDRVDiff2State {
} BDRVDiff2State;

#define HEADER_MAGIC "Diff2 Virtual HD Image 2"
#define HEADER_VERSION 0x00020002
#define HEADER_SIZE sizeof(Diff2Header)
#define GENERATION_BITS 8

#define DEBUG_DIFF2_FILE

#ifdef DEBUG_DIFF2_FILE
#define DPRINTF(fmt, ...) \
    do { printf("diff2-format: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static int diff2_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    return 100;
}

static int diff2_open(BlockDriverState *bs, int flags)
{    
}

static int diff2_read(BlockDriverState *bs, int64_t sector_num,
                     uint8_t *buf, int nb_sectors)
{
}

static int get_dirty(BDRVDiff2State *s, int64_t sector, int generation)
{
}

static int diff2_write(BlockDriverState *bs, int64_t sector_num,
                       const uint8_t *buf, int nb_sectors)
{
}

static BlockDriverAIOCB *diff2_aio_readv(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
}

static BlockDriverAIOCB *diff2_aio_writev(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
}

static void diff2_close(BlockDriverState *bs)
{
}

static int diff2_flush(BlockDriverState *bs)
{
}

static BlockDriverAIOCB *diff2_aio_flush(BlockDriverState *bs,
                                         BlockDriverCompletionFunc *cb, void *opaque)
{
}

static int64_t diff2_getlength(BlockDriverState *bs)
{
}

static int diff2_truncate(BlockDriverState *bs, int64_t offset)
{    
}

static int diff2_discard(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
}

static int diff2_is_inserted(BlockDriverState *bs)
{
}

static int diff2_eject(BlockDriverState *bs, int eject_flag)
{
}

static int diff2_set_locked(BlockDriverState *bs, int locked)
{
}

static int diff2_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
}

static BlockDriverAIOCB *diff2_aio_ioctl(BlockDriverState *bs,
                                         unsigned long int req, void *buf,
                                         BlockDriverCompletionFunc *cb, void *opaque)
{
}

static int diff2_create(const char *filename, QEMUOptionParameter *options)
{
    Diff2Header header;
    int64_t total_size = 0;
    int64_t real_size = 0;
    int64_t bitmap_size = 0;
    int64_t genmap_size = 0;
    unsigned long *bitmap = NULL;
    unsigned long *genmap = NULL;

    printf("bitmap: %s\n", __FUNCTION__);
    
    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
            total_size = options->value.n;
        }
        options++;
    }

    memset(&header, 0, sizeof(header));
    
    header.version      = HEADER_VERSION;
    header.header_size  = HEADER_SIZE;
    header.sector       = 512;
    header.total_size   = total_size; /* this is byte */
    header.mom_sign     = 0; /* mon sign, must be UUID */
    header.cur_gen      = 0; /* first generation, this is zero */

    bitmap_size = (total_size >> BDRV_SECTOR_BITS) +
        BDRV_SECTORS_PER_DIRTY_CHUNK * 8 - 1;
    bitmap_size /= BDRV_SECTORS_PER_DIRTY_CHUNK * 8;
    
    header.bitmap_size  = bitmap_size;
    DPRINTF("bitmap_size: %lf [KBytes]\n", header.bitmap_size / 1024.0);
    
    genmap_size = (bitmap_size * 8 * GENERATION_BITS) / 8;
    header.genmap_size  = genmap_size;
    DPRINTF("genmap_size: %lf [KBytes]\n", header.genmap_size / 1024.0);    
    
    bitmap = qemu_mallocz(bitmap_size);
    genmap = qemu_mallocz(genmap_size);
    
    
}

static QEMUOptionParameter diff2_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Diff2 Virtual disk size"
    },
    { NULL }
};

static int diff2_has_zero_init(BlockDriverState *bs)
{
}

static int diff2_get_dirtymap(BlockDriverState *bs, uint8_t *buf, 
                             int generation)
{
}

static int diff2_get_dirty(BlockDriverState *bs, uint64_t cur_sector,
                           int generation)
{
}

static BlockDriver bdrv_diff2 = {
    .format_name        = "diff2",

    /* It's really 0, but we need to make qemu_malloc() happy */
    .instance_size      = sizeof(BDRVDiff2State),

    .bdrv_open          = diff2_open,
    .bdrv_close         = diff2_close,
    .bdrv_read          = diff2_read,
    .bdrv_write         = diff2_write,
    .bdrv_flush         = diff2_flush,
    .bdrv_probe         = diff2_probe,
    .bdrv_getlength     = diff2_getlength,
    .bdrv_truncate      = diff2_truncate,

    .bdrv_aio_readv     = diff2_aio_readv,
    .bdrv_aio_writev    = diff2_aio_writev,
    .bdrv_aio_flush     = diff2_aio_flush,
    .bdrv_discard       = diff2_discard,

    .bdrv_is_inserted   = diff2_is_inserted,
    .bdrv_eject         = diff2_eject,
    .bdrv_set_locked    = diff2_set_locked,
    .bdrv_ioctl         = diff2_ioctl,
    .bdrv_aio_ioctl     = diff2_aio_ioctl,

    .bdrv_create        = diff2_create,
    .create_options     = diff2_create_options,
    .bdrv_has_zero_init = diff2_has_zero_init,

    .bdrv_get_block_dirtymap = diff2_get_dirtymap,
    .bdrv_get_block_dirty    = diff2_get_dirty,
};

static void bdrv_diff2_init(void)
{
    bdrv_register(&bdrv_diff2);
}

block_init(bdrv_diff2_init);

