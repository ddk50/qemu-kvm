
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"

typedef struct diff_header {
    char magic[32]; /* "Diff Virtual HD Image" */
    uint32_t version;
    uint32_t header_size;
    uint32_t sector;
    uint64_t total_size;
    uint64_t mom_sign;
    uint32_t generation;
    uint32_t bitmap_count; /* currently, always 2 (Dirty, AccDirty) */
    uint32_t bitmap_size;
    uint32_t freezed; /* if 1, does not execute */
} DiffHeader;

typedef struct BDRVDiffState {    
    uint64_t diff_sectors_offset;
    uint32_t generation;
    uint32_t mon_sign;
    int bitmap_count;   
    uint32_t bitmap_size;
    unsigned long **diff_bitmap; /* 0: Dirty, 1: AccDirty */
    uint32_t dirty_count;
    uint32_t sector;
    uint64_t total_size;
} BDRVDiffState;

#define HEADER_MAGIC "Diff Virtual HD Image"
#define HEADER_VERSION 0x00020000
#define HEADER_SIZE sizeof(DiffHeader)

//#define DEBUG_DIFF_FILE

#ifdef DEBUG_DIFF_FILE
#define DPRINTF(fmt, ...) \
    do { printf("diff-format: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static int diff_probe(const uint8_t *buf, int buf_size, const char *filename)
{
//    const struct bochs_header *diff = (const void *)buf;
    
    /* if (buf_size < HEADER_SIZE) */
    /*     return 100; */

    return 100;
}

static int diff_open(BlockDriverState *bs, int flags)
{
    struct diff_header diff;
    int i;
    uint32_t pos;
    uint64_t bitmap_size;
    BDRVDiffState *s = bs->opaque;

    if (bdrv_pread(bs->file, 0, &diff, sizeof(diff)) != sizeof(diff)) {
        DPRINTF("Could not read out header\n");
        goto fail;
    }

    if (strcmp(diff.magic, HEADER_MAGIC) ||
        ((le32_to_cpu(diff.version) != HEADER_VERSION))) {
        DPRINTF("This is not diff file format\n");
        goto fail;
    }

    assert(diff.bitmap_count == 2);

    /* read  */
    s->generation   = diff.generation;
    s->mon_sign     = diff.mom_sign;
    s->bitmap_count = diff.bitmap_count;
    s->bitmap_size  = diff.bitmap_size;
    s->diff_bitmap  = qemu_mallocz(sizeof(unsigned long*) * s->bitmap_count);
    s->dirty_count  = 0;
    s->sector       = diff.sector;
    s->total_size   = diff.total_size;

    bs->total_sectors = s->total_size / 512;
    
    for (i = 0, pos = diff.header_size; 
         i < diff.bitmap_count ; i++, pos += s->bitmap_size) {        
        s->diff_bitmap[i] = qemu_mallocz(s->bitmap_size);        
        if (bdrv_pread(bs->file, pos, s->diff_bitmap[i], s->bitmap_size)
            != s->bitmap_size) {            
            DPRINTF("Could not read bitmap\n");
            goto fail;
        }        
    }
    
    /* offset bytes */
    s->diff_sectors_offset = (((s->bitmap_count * s->bitmap_size) 
                               + sizeof(struct diff_header))
                              + 511) & ~511;

    /* tracing bitmap */
    bitmap_size = (s->total_size >> BDRV_SECTOR_BITS) +
        BDRV_SECTORS_PER_DIRTY_CHUNK * 8 - 1;
    bitmap_size /= BDRV_SECTORS_PER_DIRTY_CHUNK * 8;   
//    s->dirty_bitmap = qemu_mallocz(bitmap_size);

    printf("kaz s->total_size: %llu\n", s->total_size);
    printf("kaz bitmapsize: %u\n", s->bitmap_size);
    printf("kaz BDRV_SECTOR_BITS: %d\n", BDRV_SECTOR_BITS);
    printf("kaz BDRV_SECTORS_PER_DIRTY_CHUNK: %d\n", BDRV_SECTOR_BITS);
    printf("kaz bytes per dirty_chunk: %d\n", BDRV_SECTORS_PER_DIRTY_CHUNK << BDRV_SECTOR_BITS);
    printf("kaz 1 sector size: %d\n", 1 << BDRV_SECTOR_BITS);

    printf("bitmap_size = (s->total_size >> BDRV_SECTOR_BITS): %llu\n",
	   (s->total_size >> BDRV_SECTOR_BITS));

    printf("BDRV_SECTORS_PER_DIRTY_CHUNK * 8: %d\n", BDRV_SECTORS_PER_DIRTY_CHUNK * 8);

    return 0;
    
fail:
    for (i = 0 ; i < s->bitmap_count ; i++)
        qemu_free(s->diff_bitmap[i]);    
    qemu_free(s->diff_bitmap);    
    return -1;
}

static int diff_read(BlockDriverState *bs, int64_t sector_num,
                     uint8_t *buf, int nb_sectors)
{
    BDRVDiffState *s = bs->opaque;    
    DPRINTF("read: %lld %s\n", sector_num, __FUNCTION__);    
    return bdrv_read(bs->file,
                     sector_num + (s->diff_sectors_offset / 512),
                     buf, nb_sectors);
}

static void set_dirty_bitmap(BlockDriverState *bs, int64_t sector_num,
                             int nb_sectors, int dirty, int generation)
{
    BDRVDiffState *s = bs->opaque;
    int64_t start, end;
    unsigned long val, idx, bit;

    start = sector_num / BDRV_SECTORS_PER_DIRTY_CHUNK;
    end = (sector_num + nb_sectors - 1) / BDRV_SECTORS_PER_DIRTY_CHUNK;

    for (; start <= end; start++) {
        idx = start / (sizeof(unsigned long) * 8);
        bit = start % (sizeof(unsigned long) * 8);
        val = s->diff_bitmap[generation][idx];
        if (dirty) {
            if (!(val & (1UL << bit))) {
                s->dirty_count++;
                val |= 1UL << bit;
            }
        } else {
            if (val & (1UL << bit)) {
                s->dirty_count--;
                val &= ~(1UL << bit);
            }
        }
        s->diff_bitmap[generation][idx] = val;
    }

    /* TODO: write diff_bitmap to physical disk */
}

static int get_dirty(BDRVDiffState *s, int64_t sector, int generation)
{
    int64_t chunk = sector / (int64_t)BDRV_SECTORS_PER_DIRTY_CHUNK;

    assert(s->total_size != 0);

    if (s->diff_bitmap[generation] &&
        (sector << BDRV_SECTOR_BITS) < s->total_size) {
        return !!(s->diff_bitmap[generation][chunk / (sizeof(unsigned long) * 8)] &
            (1UL << (chunk % (sizeof(unsigned long) * 8))));
    } else {
        return 0;
    }
}

static int diff_write(BlockDriverState *bs, int64_t sector_num,
                      const uint8_t *buf, int nb_sectors)
{
    BDRVDiffState *s = bs->opaque;
    
    set_dirty_bitmap(bs, sector_num, nb_sectors, 1, 0);    
    set_dirty_bitmap(bs, sector_num, nb_sectors, 1, 1);

    DPRINTF("write: %lld %s\n", sector_num, __FUNCTION__);
    
    return bdrv_write(bs->file, 
                      sector_num + (s->diff_sectors_offset / 512), 
                      buf, nb_sectors);
}

static BlockDriverAIOCB *diff_aio_readv(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVDiffState *s = bs->opaque;

    DPRINTF("read: %lld\n", sector_num);
    DPRINTF("%s\n", __FUNCTION__);
    
    return bdrv_aio_readv(bs->file, 
                          sector_num + (s->diff_sectors_offset / 512),
                          qiov, nb_sectors, cb, opaque);
}

static BlockDriverAIOCB *diff_aio_writev(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVDiffState *s = bs->opaque;

    set_dirty_bitmap(bs, sector_num, nb_sectors, 1, 0);
    set_dirty_bitmap(bs, sector_num, nb_sectors, 1, 1);
    
    return bdrv_aio_writev(bs->file,
                           sector_num + (s->diff_sectors_offset / 512), 
                           qiov, nb_sectors, cb, opaque);
}

static void diff_close(BlockDriverState *bs)
{
    BDRVDiffState *s = bs->opaque;
    int i;

//    qemu_free(s->dirty_bitmap);

    for (i = 0 ; i < s->bitmap_count ; i++)
        qemu_free(s->diff_bitmap[i]);    
    qemu_free(s->diff_bitmap);    
}

static int diff_flush(BlockDriverState *bs)
{
    return bdrv_flush(bs->file);
}

static BlockDriverAIOCB *diff_aio_flush(BlockDriverState *bs,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_flush(bs->file, cb, opaque);
}

static int64_t diff_getlength(BlockDriverState *bs)
{
    BDRVDiffState *s = bs->opaque;
//    return bdrv_getlength(bs->file) - s->diff_sectors_offset;   
    return s->total_size;
}

static int diff_truncate(BlockDriverState *bs, int64_t offset)
{    
    BDRVDiffState *s = bs->opaque;
    return bdrv_truncate(bs->file, offset + s->diff_sectors_offset);
}

static int diff_discard(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    BDRVDiffState *s = bs->opaque;
    return bdrv_discard(bs->file, 
                        sector_num + (s->diff_sectors_offset / 512), 
                        nb_sectors);
}

static int diff_is_inserted(BlockDriverState *bs)
{
    return bdrv_is_inserted(bs->file);
}

static int diff_eject(BlockDriverState *bs, int eject_flag)
{
    return bdrv_eject(bs->file, eject_flag);
}

static int diff_set_locked(BlockDriverState *bs, int locked)
{
    bdrv_set_locked(bs->file, locked);
    return 0;
}

static int diff_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
    return bdrv_ioctl(bs->file, req, buf);
}

static BlockDriverAIOCB *diff_aio_ioctl(BlockDriverState *bs,
        unsigned long int req, void *buf,
        BlockDriverCompletionFunc *cb, void *opaque)
{
   return bdrv_aio_ioctl(bs->file, req, buf, cb, opaque);
}

static int diff_create(const char *filename, QEMUOptionParameter *options)
{
    int fd;
    int result = 0;
    int64_t total_size = 0;
    int64_t real_size = 0;
    int64_t bitmap_size = 0;
    unsigned long *bitmap = NULL;
    
    DiffHeader header;
    
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
    header.mom_sign     = 0; /* mon sign */
    header.generation   = 0; /* one */
    header.bitmap_count = 2; /* currently, always 2 (Dirty, AccDirty) */
    header.sector       = 512;
    header.total_size   = total_size;

    bitmap_size = (total_size >> BDRV_SECTOR_BITS) +
        BDRV_SECTORS_PER_DIRTY_CHUNK * 8 - 1;
    bitmap_size /= BDRV_SECTORS_PER_DIRTY_CHUNK * 8;
    header.bitmap_size  = bitmap_size;
    
    uint64_t total_bitmap_size = bitmap_size * header.bitmap_count;
    bitmap = qemu_mallocz(total_bitmap_size);
    DPRINTF("bitmap: %lf [KBytes]\n", header.bitmap_size / 1024.0);

    real_size = total_size + sizeof(header) + total_bitmap_size;
    DPRINTF("real_size: %lf [GBytes]\n", real_size / 1024.0 / 1024.0 / 1024.0);

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
              0644);    
    if (fd < 0) {
        result = -errno;
    } else {        
        /* write header */
        if (qemu_write_full(fd, &header, sizeof(header)) 
            != sizeof(header)) {
            result = -errno;            
            goto exit;
        }
        
        if (qemu_write_full(fd, bitmap, total_bitmap_size) != 
            total_bitmap_size) {
            result = -errno;
            goto exit;
        }
        
        if (ftruncate(fd, real_size) != 0) {
            result = -errno;
        }
        if (close(fd) != 0) {
            result = -errno;
        }        
    }

exit:
    qemu_free(bitmap);
    return result;
}

static QEMUOptionParameter diff_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Diff Virtual disk size"
    },
    { NULL }
};

static int diff_has_zero_init(BlockDriverState *bs)
{
    return bdrv_has_zero_init(bs->file);
}

static int diff_get_dirtymap(BlockDriverState *bs, uint8_t *buf, 
                             int generation)
{
    BDRVDiffState *s = bs->opaque;    
    if (buf == NULL)
        return s->bitmap_size;
    memcpy(buf, s->diff_bitmap[generation], s->bitmap_size);
    return s->bitmap_size;
}

static int diff_get_dirty(BlockDriverState *bs, uint64_t cur_sector,
                          int generation)
{
    BDRVDiffState *s = bs->opaque;
    return get_dirty(s, cur_sector, generation);
}

static BlockDriver bdrv_diff = {
    .format_name        = "diff",

    /* It's really 0, but we need to make qemu_malloc() happy */
    .instance_size      = sizeof(BDRVDiffState),

    .bdrv_open          = diff_open,
    .bdrv_close         = diff_close,
    .bdrv_read          = diff_read,
    .bdrv_write         = diff_write,
    .bdrv_flush         = diff_flush,
    .bdrv_probe         = diff_probe,
    .bdrv_getlength     = diff_getlength,
    .bdrv_truncate      = diff_truncate,

    .bdrv_aio_readv     = diff_aio_readv,
    .bdrv_aio_writev    = diff_aio_writev,
    .bdrv_aio_flush     = diff_aio_flush,
    .bdrv_discard       = diff_discard,

    .bdrv_is_inserted   = diff_is_inserted,
    .bdrv_eject         = diff_eject,
    .bdrv_set_locked    = diff_set_locked,
    .bdrv_ioctl         = diff_ioctl,
    .bdrv_aio_ioctl     = diff_aio_ioctl,

    .bdrv_create        = diff_create,
    .create_options     = diff_create_options,
    .bdrv_has_zero_init = diff_has_zero_init,

    .bdrv_get_block_dirtymap = diff_get_dirtymap,
    .bdrv_get_block_dirty    = diff_get_dirty,
};

static void bdrv_diff_init(void)
{
    bdrv_register(&bdrv_diff);
}

block_init(bdrv_diff_init);

