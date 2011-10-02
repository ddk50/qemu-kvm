
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
    uint32_t cur_gen;
    uint64_t mom_sign;
    uint32_t sector;
    uint64_t total_size;
    uint64_t genmap_size;
    uint64_t bitmap_size;
    unsigned long *bitmap;
    unsigned long *genmap;
    uint64_t diff2_sectors_offset;
} BDRVDiff2State;

#define HEADER_MAGIC    "Diff2 Virtual HD Image 2"
#define HEADER_VERSION  0x00020002
#define HEADER_SIZE     sizeof(Diff2Header)
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
    const struct diff2_header *diff2 = (const void *)buf;

    if ((buf_size >= HEADER_SIZE) &&
        (strcmp(diff2->magic, HEADER_MAGIC) == 0) &&
        (diff2->version == HEADER_VERSION)) {
        DPRINTF("This is diff2 format\n");
        return 100;    
    } else {
        return 0;
    }
    
    return 100;
}

static int diff2_open(BlockDriverState *bs, int flags)
{
    struct diff2_header diff2;
    int i;    
    uint32_t pos;
    BDRVDiff2State *s = bs->opaque;
    
    DPRINTF("%s\n", __FUNCTION__);

    if (bdrv_pread(bs->file, 0, &diff2, sizeof(diff2)) 
        != sizeof(diff2)) {
        DPRINTF("Could not read out header");
    }

    if (strcmp(diff2.magic, HEADER_MAGIC) ||
        (le32_to_cpu(diff2.version) != HEADER_VERSION)) {
        DPRINTF("This is not diff2 file format\n");
        goto fail;
    }

    /* read */
    s->cur_gen     = diff2.cur_gen;
    s->mom_sign    = diff2.mom_sign;
    s->sector      = diff2.sector;
    s->total_size  = diff2.total_size;
    s->bitmap_size = diff2.bitmap_size;
    s->genmap_size = diff2.genmap_size;
    
    /* 
     * calculate total sectors
     */
    bs->total_sectors = s->total_size / 512;

    /*
     * read out genmap
     */
    s->genmap = qemu_mallocz(s->genmap_size);
    DPRINTF("s->genmap: %p\n", s->genmap);
    assert(s->genmap != NULL);

    /*
     * read out bitmap
     */
    s->bitmap = qemu_mallocz(s->bitmap_size);
    DPRINTF("s->bitmap: %p\n", s->bitmap);
    assert(s->bitmap != NULL);

    
    pos = diff2.header_size;
    
    if (bdrv_pread(bs->file, pos, s->bitmap, s->bitmap_size)
        != s->bitmap_size) {
        DPRINTF("Could not read out bitmap\n");
        goto fail;
    }

    if (bdrv_pread(bs->file, pos + s->bitmap_size, s->genmap, s->genmap_size)
        != s->genmap_size) {
        DPRINTF("Could not read out genmap\n");
        goto fail;
    }

    /* 
     * offset bytes
     * 512 bytes align 
     */
    s->diff2_sectors_offset = (((s->bitmap_size + s->genmap_size) 
                               + sizeof(struct diff2_header))
                              + 511) & ~511;

    DPRINTF("diff2_sectors_offset: %llu\n", s->diff2_sectors_offset);
    DPRINTF("bitmap_size: %llu \n", s->bitmap_size);
    DPRINTF("genmap_size: %llu \n", s->genmap_size);

    return 0;

fail:
    qemu_free(s->genmap);
    qemu_free(s->bitmap);

    return -1;
}

static int diff2_read(BlockDriverState *bs, int64_t sector_num,
                     uint8_t *buf, int nb_sectors)
{
    BDRVDiff2State *s = bs->opaque;
    DPRINTF("=============oh shit!!!==============");
    return bdrv_read(bs->file,
                     sector_num + (s->diff2_sectors_offset / 512),
                     buf, nb_sectors);    
}

static int get_dirty(BDRVDiff2State *s, int64_t sector, int generation)
{
    return 0;
}

static int diff2_write(BlockDriverState *bs, int64_t sector_num,
                       const uint8_t *buf, int nb_sectors)
{
    BDRVDiff2State *s = bs->opaque;    
    return bdrv_write(bs->file, 
                      sector_num + (s->diff2_sectors_offset / 512), 
                      buf, nb_sectors);
}

static BlockDriverAIOCB *diff2_aio_readv(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVDiff2State *s = bs->opaque;    
    return bdrv_aio_readv(bs->file, 
                          sector_num + (s->diff2_sectors_offset / 512),
                          qiov, nb_sectors, cb, opaque);
}

static BlockDriverAIOCB *diff2_aio_writev(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVDiff2State *s = bs->opaque;    
    return bdrv_aio_writev(bs->file,
                           sector_num + (s->diff2_sectors_offset / 512), 
                           qiov, nb_sectors, cb, opaque);
}

static void diff2_close(BlockDriverState *bs)
{
    BDRVDiff2State *s = bs->opaque;
    qemu_free(s->genmap);
    qemu_free(s->bitmap);
}

static int diff2_flush(BlockDriverState *bs)
{
    return bdrv_flush(bs->file);
}

static BlockDriverAIOCB *diff2_aio_flush(BlockDriverState *bs,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_flush(bs->file, cb, opaque);
}

static int64_t diff2_getlength(BlockDriverState *bs)
{
    BDRVDiff2State *s = bs->opaque;
    DPRINTF("total_size: %llu\n", s->total_size);
    return s->total_size;
}

static int diff2_truncate(BlockDriverState *bs, int64_t offset)
{    
    BDRVDiff2State *s = bs->opaque;
    return bdrv_truncate(bs->file, offset + s->diff2_sectors_offset);
}

static int diff2_discard(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    BDRVDiff2State *s = bs->opaque;
    return bdrv_discard(bs->file, 
                        sector_num + (s->diff2_sectors_offset / 512), 
                        nb_sectors);
}

static int diff2_is_inserted(BlockDriverState *bs)
{
    return bdrv_is_inserted(bs->file);
}

static int diff2_eject(BlockDriverState *bs, int eject_flag)
{
    return bdrv_eject(bs->file, eject_flag);
}

static int diff2_set_locked(BlockDriverState *bs, int locked)
{
    bdrv_set_locked(bs->file, locked);
    return 0;
}

static int diff2_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
    return bdrv_ioctl(bs->file, req, buf);
}

static BlockDriverAIOCB *diff2_aio_ioctl(BlockDriverState *bs,
                                         unsigned long int req, void *buf,
                                         BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_ioctl(bs->file, req, buf, cb, opaque);
}

static int diff2_create(const char *filename, QEMUOptionParameter *options)
{
    int fd;
    int result = 0;
    int64_t total_size = 0;
    int64_t real_size = 0;
    int64_t bitmap_size = 0;
    int64_t genmap_size = 0;
    unsigned long *bitmap = NULL;
    unsigned long *genmap = NULL;
    Diff2Header header;
    
    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
            total_size = options->value.n;
        }
        options++;
    }

    memset(&header, 0, sizeof(header));

    memcpy(header.magic, HEADER_MAGIC, sizeof(HEADER_MAGIC));
    header.version      = HEADER_VERSION;
    header.header_size  = HEADER_SIZE;
    header.sector       = 512;
    header.total_size   = total_size; /* this is byte */
    header.mom_sign     = 0; /* mom sign, must be UUID */
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
    assert(bitmap != NULL);
    genmap = qemu_mallocz(genmap_size);
    assert(genmap != NULL);

    /* total file size */
    real_size = total_size + genmap_size + 
        bitmap_size + HEADER_SIZE;
    
    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
              0644);

    if (fd < 0) {
        result = -errno;
    } else {

        /* first, write header */
        if (qemu_write_full(fd, &header, sizeof(header))
            != sizeof(header)) {
            result = -errno;
            goto exit;
        } 

        /* second, write bitmap */
        if (qemu_write_full(fd, bitmap, bitmap_size) !=
            bitmap_size) {
            result = -errno;
            goto exit;
        }

        /* finally, write generation map */
        if (qemu_write_full(fd, genmap, genmap_size) !=
            genmap_size) {
            result = -errno;
            goto exit;
        }

        /* allocate region */
        if (ftruncate(fd, real_size) != 0) {
            result = -errno;
        }

        /* close */
        if (close(fd) != 0) {
            result = -errno;
        }
    }

exit:
    qemu_free(bitmap);
    qemu_free(genmap);
    return result;
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
    return bdrv_has_zero_init(bs->file);
}

static int diff2_get_dirtymap(BlockDriverState *bs, uint8_t *buf, 
                              int generation)
{
    BDRVDiff2State *s = bs->opaque;    
    return s->bitmap_size;
}

static int diff2_get_dirty(BlockDriverState *bs, uint64_t cur_sector,
                           int generation)
{
    BDRVDiff2State *s = bs->opaque;
    return get_dirty(s, cur_sector, generation);
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
