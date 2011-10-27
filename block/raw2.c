
#include "qemu-common.h"
#include "block_int.h"
#include "module.h"

typedef struct raw2_header {
    char magic[32];
    uint64_t total_size;
} Raw2Header;

typedef struct Raw2State {
    uint64_t total_size;
    uint64_t raw2_sectors_offset;
} Raw2State;

#define FORMAT_NAME    "raw2"
#define HEADER_MAGIC   "raw2 Virtual HD Image"
#define HEADER_SIZE    sizeof(Raw2Header)

#define DEBUG_RAW2_FILE

#ifdef DEBUG_RAW2_FILE
#define DPRINTF(fmt, ...) \
    do { printf("raw2-format: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static int raw2_open(BlockDriverState *bs, int flags)
{
    struct raw2_header raw2;
    Raw2State *s = bs->opaque;

    bs->sg = bs->file->sg;

    if (bdrv_pread(bs->file, 0, &raw2, sizeof(raw2))
        != sizeof(raw2)) {
        DPRINTF("Could not read out header");
        goto fail;
    }

    printf("kazushi: %s\n", raw2.magic);

    if (strcmp(raw2.magic, HEADER_MAGIC)) {
        DPRINTF("This is not raw2 file format\n");
        goto fail;
    }

    s->total_size = raw2.total_size;
    s->raw2_sectors_offset = (sizeof(struct raw2_header) 
                              + 511) & ~511;

    printf("s->raw2_sectors_offset: %lld\n", s->raw2_sectors_offset);

    bs->total_sectors = s->total_size / 512;
    
    return 0;

fail:
    return -1;
}

static int raw2_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{    
    Raw2State *s = bs->opaque;
    return bdrv_read(bs->file, 
                     sector_num + (s->raw2_sectors_offset / 512), 
                     buf, nb_sectors);
}

static int raw2_write(BlockDriverState *bs, int64_t sector_num,
                     const uint8_t *buf, int nb_sectors)
{
    Raw2State *s = bs->opaque;
    return bdrv_write(bs->file, 
                      sector_num + (s->raw2_sectors_offset / 512), 
                      buf, 
                      nb_sectors);
}

static BlockDriverAIOCB *raw2_aio_readv(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    Raw2State *s = bs->opaque;
    return bdrv_aio_readv(bs->file, 
                          sector_num + (s->raw2_sectors_offset / 512), 
                          qiov, nb_sectors, cb, opaque);
}

static BlockDriverAIOCB *raw2_aio_writev(BlockDriverState *bs,
    int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    Raw2State *s = bs->opaque;
    return bdrv_aio_writev(bs->file,
                           sector_num + (s->raw2_sectors_offset / 512), 
                           qiov, nb_sectors, cb, opaque);
}

static void raw2_close(BlockDriverState *bs)
{
}

static int raw2_flush(BlockDriverState *bs)
{
    return bdrv_flush(bs->file);
}

static BlockDriverAIOCB *raw2_aio_flush(BlockDriverState *bs,
    BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_flush(bs->file, cb, opaque);
}

static int64_t raw2_getlength(BlockDriverState *bs)
{
    return bdrv_getlength(bs->file);
}

static int raw2_truncate(BlockDriverState *bs, int64_t offset)
{
    Raw2State *s = bs->opaque;
    return bdrv_truncate(bs->file, 
                         offset + (s->raw2_sectors_offset / 512));
}

static int raw2_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    const struct raw2_header *raw2 = (const void *)buf;
    if ((buf_size >= HEADER_SIZE) &&
        (strcmp(raw2->magic, HEADER_MAGIC) == 0)) {
        printf("This is raw2 format\n");
        return 100;
    } else {
        return 0;
    }
}

static int raw2_discard(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    Raw2State *s = bs->opaque;
    return bdrv_discard(bs->file, 
                        sector_num + (s->raw2_sectors_offset / 512),
                        nb_sectors);
}

static int raw2_is_inserted(BlockDriverState *bs)
{
    return bdrv_is_inserted(bs->file);
}

static int raw2_eject(BlockDriverState *bs, int eject_flag)
{
    return bdrv_eject(bs->file, eject_flag);
}

static int raw2_set_locked(BlockDriverState *bs, int locked)
{
    bdrv_set_locked(bs->file, locked);
    return 0;
}

static int raw2_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
   return bdrv_ioctl(bs->file, req, buf);
}

static BlockDriverAIOCB *raw2_aio_ioctl(BlockDriverState *bs,
        unsigned long int req, void *buf,
        BlockDriverCompletionFunc *cb, void *opaque)
{
   return bdrv_aio_ioctl(bs->file, req, buf, cb, opaque);
}

static int raw2_create(const char *filename, QEMUOptionParameter *options)
{
    int fd;
    int64_t total_size = 0;
    int64_t real_size;
    Raw2Header header;
    
    /* Read out options */
    while (options && options->name) {
        if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
            total_size = options->value.n;
        }
        options++;
    }    

    memset(&header, 0, sizeof(header));
    
    memcpy(header.magic, HEADER_MAGIC, sizeof(HEADER_MAGIC));
    header.total_size = total_size;

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
              0644);

    if (fd < 0) {
        return -errno;
    }

    if (qemu_write_full(fd, &header, sizeof(header))
        != sizeof(header)) {
        return -errno;       
    }

    /* total file size */
    real_size = total_size + sizeof(Raw2Header);

    /* allocate region */
    if (ftruncate(fd, real_size) != 0) {
        return -errno;
    }

    close(fd);
    
    /* return bdrv_create_file(filename, options); */
    return 0;    
}

static QEMUOptionParameter raw2_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    { NULL }
};

static int raw2_has_zero_init(BlockDriverState *bs)
{
    return bdrv_has_zero_init(bs->file);
}

static BlockDriver bdrv_raw2 = {
    .format_name        = "raw2",

    /* It's really 0, but we need to make qemu_malloc() happy */
    .instance_size      = sizeof(Raw2State),

    .bdrv_open          = raw2_open,
    .bdrv_close         = raw2_close,
    .bdrv_read          = raw2_read,
    .bdrv_write         = raw2_write,
    .bdrv_flush         = raw2_flush,
    .bdrv_probe         = raw2_probe,
    .bdrv_getlength     = raw2_getlength,
    .bdrv_truncate      = raw2_truncate,

    .bdrv_aio_readv     = raw2_aio_readv,
    .bdrv_aio_writev    = raw2_aio_writev,
    .bdrv_aio_flush     = raw2_aio_flush,
    .bdrv_discard       = raw2_discard,

    .bdrv_is_inserted   = raw2_is_inserted,
    .bdrv_eject         = raw2_eject,
    .bdrv_set_locked    = raw2_set_locked,
    .bdrv_ioctl         = raw2_ioctl,
    .bdrv_aio_ioctl     = raw2_aio_ioctl,

    .bdrv_create        = raw2_create,
    .create_options     = raw2_create_options,
    .bdrv_has_zero_init = raw2_has_zero_init,
};

static void bdrv_raw2_init(void)
{
    bdrv_register(&bdrv_raw2);
}

block_init(bdrv_raw2_init);
