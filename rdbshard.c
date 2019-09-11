/*
 *  rdbshard -- create twemproxy-compatible shards of Redis rdb files
 *  Copyright (C) 2013 Wiktor Janas <wixorpeek@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <endian.h>
#include <time.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "lzf.h"
#include "md5.h"

uint64_t crc64(uint64_t crc, const unsigned char *s, size_t l);

/* ------------------------------------------------------------------------- */

typedef uint32_t hash_t;

struct hashfn_descriptor {
    const char *name;
    hash_t (*fn)(const void *key, size_t keylen);
};
typedef const struct hashfn_descriptor *hashfn_t;

static const struct hashfn_descriptor fnv1a_64_descriptor; /* forward decl */
static const struct hashfn_descriptor * const all_hashfns[] = {
    &fnv1a_64_descriptor,
    NULL
};

static const struct hashfn_descriptor *default_hashfn = &fnv1a_64_descriptor;

static hashfn_t hashfn_init(const char *name)
{
    const struct hashfn_descriptor * const *ret = all_hashfns;

    while(*ret != NULL)
        if(0 == strcmp((*ret)->name, name))
            return *ret;
        else
            ret++;

    errno = ENOENT;
    return NULL;
}

static inline const char *hashfn_name(hashfn_t hfn) {
    return hfn->name;
}
static inline hash_t hashfn_hash(hashfn_t hfn, const void *key, size_t keylen) {
    return hfn->fn(key, keylen);
}

/* ------------------------------------------------------------------------- */

struct shardfn_descriptor;
typedef const struct shardfn_descriptor* const * shardfn_t;

struct shardfn_descriptor {
    const char *name;
    shardfn_t (*init)(const struct shardfn_descriptor *d, const char *node_names[], int node_count);
    int (*dispatch)(shardfn_t sfn, hash_t hash);
    void (*free)(shardfn_t sfn);
};

static const struct shardfn_descriptor ketama_descriptor; /* forward decl */
static const struct shardfn_descriptor * const all_shardfns[] = {
    &ketama_descriptor,
    NULL
};

static const struct shardfn_descriptor *default_shardfn = &ketama_descriptor;

static shardfn_t shardfn_init(const char *name, const char *node_names[], int node_count)
{
    const struct shardfn_descriptor * const *ret = all_shardfns;
    while(*ret != NULL)
        if(0 == strcmp((*ret)->name, name))
            return (*ret)->init(*ret, node_names, node_count);
        else
            ret++;

    errno = ENOENT;
    return NULL;
}
static inline const char *shardfn_name(shardfn_t sfn) {
    return (*sfn)->name;
}
static inline int shardfn_dispatch(shardfn_t sfn, hash_t hash) {
    return (*sfn)->dispatch(sfn, hash);
}
static inline void shardfn_free(shardfn_t sfn) {
    (*sfn)->free(sfn);
}

/* ------------------------------------------------------------------------- */

static hash_t fnv1a_64(const void *key, size_t keylen)
{
    const uint8_t *p = key, *q = p + keylen;

    hash_t ret = 0x84222325;
    while(p < q)
        ret = (ret ^ *p++) * 0x1b3;
    return ret;
}
static const struct hashfn_descriptor fnv1a_64_descriptor = {
    .name = "fnv1a_64", .fn = fnv1a_64
};

/* ------------------------------------------------------------------------- */

struct ketama_point {
    hash_t hash;
    int idx;
};
struct ketama {
    const struct shardfn_descriptor *descriptor;
    int n_points;
    struct ketama_point *points;
};

static int ketama_pointcmp(const void *p1, const void *p2)
{
    const struct ketama_point *point1 = p1, *point2 = p2;
    if(point1->hash > point2->hash)
        return 1;
    if(point1->hash < point2->hash)
        return -1;
    return 0;
}

static shardfn_t ketama_init(const struct shardfn_descriptor *d, const char *node_names[], int node_count)
{
    const int points_per_node = 160;

    struct ketama *ketama = malloc(sizeof(struct ketama));
    if(NULL == ketama)
        return NULL;

    ketama->descriptor = d;
    ketama->n_points = node_count * points_per_node;
    ketama->points = malloc(sizeof(struct ketama_point) * ketama->n_points);
    if(NULL == ketama->points) {
        free(ketama);
        return NULL;
    }

    int maxnamelen = 0;
    for(int i=0; i<node_count; i++) {
        int namelen = strlen(node_names[i]);
        if(maxnamelen < namelen)
            maxnamelen = namelen;
    }

    struct ketama_point *p = ketama->points;

    for(int i=0; i<node_count; i++)
        for(int j=0; j<points_per_node/4; j++)
        {
            char buf[maxnamelen + 16];
            int len = sprintf(buf, "%s-%d", node_names[i], j);

            unsigned char md5[16];
            MD5_CTX md5_ctx;
            MD5_Init(&md5_ctx);
            MD5_Update(&md5_ctx, buf, len);
            MD5_Final(md5, &md5_ctx);

            for(int k=0; k<16; k+=4)
            {
                p->idx = i;
                p->hash = (hash_t)md5[k+3] << 24 |
                          (hash_t)md5[k+2] << 16 |
                          (hash_t)md5[k+1] <<  8 |
                          (hash_t)md5[k+0];
                p++;
            }
        }

    qsort(ketama->points, ketama->n_points, sizeof(*ketama->points), ketama_pointcmp);

    return &ketama->descriptor;
}

static int ketama_dispatch(shardfn_t sfn, hash_t hash)
{
    const struct ketama *ketama = (const struct ketama *)sfn;

    int p = 0, q = ketama->n_points;

    if(ketama->points[0].hash >= hash ||
       ketama->points[q-1].hash < hash)
        return ketama->points[0].idx;

    while(q-p > 1) {
        int m = (p+q)/2;
        if(ketama->points[m].hash < hash)
            p = m;
        else
            q = m;
    }

    return ketama->points[q].idx;
}

static void ketama_free(shardfn_t sfn)
{
    struct ketama *ketama = (struct ketama *)sfn;
    free(ketama->points);
    free(ketama);
}

static const struct shardfn_descriptor ketama_descriptor = {
    .name = "ketama",
    .init = ketama_init,
    .dispatch = ketama_dispatch,
    .free = ketama_free
};

/* ------------------------------------------------------------------------- */

enum { IO_BUFFER_SIZE = 3*4096 };

struct reader
{
    int fd;
    const char *name;

    char *buf, *pin, *rdptr, *wrptr, *end;
    uint64_t crc64;
    off_t total_size, processed_size;
};

struct writer
{
    int fd;
    char *buf, *ptr, *mid, *end;
    int mute;
    int crc_enable;
    uint64_t crc64;
};



static int reader_init(struct reader *rd, int fd, const char *name)
{
    rd->fd = fd;
    rd->name = name;

    struct stat statbuf;
    if(-1 == fstat(rd->fd, &statbuf))
        return -1;
    rd->total_size = S_ISREG(statbuf.st_mode) ? statbuf.st_size : 0;
    rd->processed_size = 0;

    rd->buf = malloc(IO_BUFFER_SIZE);
    if(NULL == rd->buf)
        return -1;
    rd->end = rd->buf + IO_BUFFER_SIZE;
    rd->rdptr = rd->wrptr = rd->buf;
    rd->pin = NULL;
    rd->crc64 = 0;
    return 0;
}

static ssize_t reader_ahead(struct reader *rd, size_t n)
{
    while(rd->rdptr + n > rd->wrptr)
    {
        size_t slide = (NULL != rd->pin ? rd->pin : rd->rdptr) - rd->buf;
        if(rd->rdptr + n > rd->end && slide > 0)
        {
            memmove(rd->buf, rd->buf+slide, rd->wrptr - rd->buf - slide);
            if(NULL != rd->pin) rd->pin -= slide;
            rd->rdptr -= slide;
            rd->wrptr -= slide;
        }

        if(rd->rdptr + n > rd->end)
        {
            size_t current = rd->end - rd->buf,
                   need = rd->rdptr+n - rd->buf;
            if(need < 2*current)
                need = 2*current;

            char *newbuf = realloc(rd->buf, need);
            if(NULL == newbuf)
                return -1;

            if(NULL != rd->pin)
                rd->pin += newbuf - rd->buf;
            rd->rdptr += newbuf - rd->buf;
            rd->wrptr += newbuf - rd->buf;
            rd->buf = newbuf;
            rd->end = newbuf + need;
        }

        size_t read_chunk = (size_t)(rd->rdptr + n - rd->wrptr);
        if(read_chunk < IO_BUFFER_SIZE)
            read_chunk = IO_BUFFER_SIZE;
        if(rd->wrptr + read_chunk > rd->end)
            read_chunk = (size_t)(rd->end - rd->wrptr);

        ssize_t rc = read(rd->fd, rd->wrptr, read_chunk);
        if(-1 == rc) {
            if(EINTR == errno)
                continue;
            return -1;
        }
        if(0 == rc)
            break;

        rd->wrptr += rc;
    }

    return rd->wrptr - rd->rdptr;
}

static inline void reader_advance(struct reader *rd, size_t n)
{
    assert(rd->rdptr + n <= rd->wrptr);
    rd->crc64 = crc64(rd->crc64, (unsigned char *)rd->rdptr, n);
    rd->processed_size += n;
    rd->rdptr += n;
}

static inline void reader_pin(struct reader *rd) {
    rd->pin = rd->rdptr;
}
static inline void reader_unpin(struct reader *rd) {
    rd->pin = NULL;
}

static inline void reader_free(struct reader *rd) {
    free(rd->buf);
}



static int writer_init(struct writer *wr, int fd)
{
    wr->fd = fd;
    wr->buf = malloc(2 * IO_BUFFER_SIZE);
    if(NULL == wr->buf)
        return -1;
    wr->ptr = wr->buf;
    wr->mid = wr->buf + IO_BUFFER_SIZE;
    wr->end = wr->buf + 2*IO_BUFFER_SIZE;
    wr->mute = 0;
    wr->crc_enable = 1;
    wr->crc64 = 0;
    return 0;
}

static int writer_loop(int fd, const char *p, const char *q)
{
    while(p < q)
    {
        ssize_t rc = write(fd, p, q-p);
        if(-1 == rc) {
            if(EINTR == errno)
                continue;
            return -1;
        }
        p += rc;
    }

    return 0;
}

static int writer_flush(struct writer *wr)
{
    if(wr->ptr == wr->buf)
        return 0;

    if(-1 == writer_loop(wr->fd, wr->buf, wr->ptr))
        return -1;

    wr->ptr = wr->buf;
    return 0;
}

static int writer_write(struct writer *wr, const void *buf, size_t n)
{
    if(wr->mute)
        return 0;

    if(wr->crc_enable)
        wr->crc64 = crc64(wr->crc64, buf, n);

    if(wr->ptr + n <= wr->end) {
        memcpy(wr->ptr, buf, n);
        wr->ptr += n;
        n = 0;
    }

    if(wr->ptr >= wr->mid || n > 0)
        if(-1 == writer_flush(wr))
            return -1;

    return writer_loop(wr->fd, buf, buf+n);
}

static inline void writer_free(struct writer *wr) {
    free(wr->buf);
}



static ssize_t xfer_pinned(struct reader *rd, struct writer *wr)
{
    ssize_t rc = writer_write(wr, rd->pin, rd->rdptr - rd->pin);
    if(-1 != rc)
        reader_unpin(rd);
    return rc;
}

static ssize_t xfer_bytes(struct reader *rd, struct writer *wr, size_t n)
{
    ssize_t total = 0,
            avail = reader_ahead(rd, 0);

    while(n > 0)
    {
        if(-1 == avail)
            return -1;
        if((size_t)avail > n)
            avail = n;

        if(-1 == writer_write(wr, rd->rdptr, avail))
            return -1;

        reader_advance(rd, avail);
        n -= avail;
        total += avail;

        avail = reader_ahead(rd, n > IO_BUFFER_SIZE ? IO_BUFFER_SIZE : n);
    }

    return total;
}

/* ------------------------------------------------------------------------- */

#define errmsg(fmt, ...) fprintf(stderr, "%s (%s): " fmt "\n", program_invocation_short_name, __FUNCTION__, ## __VA_ARGS__)
#define failerr(fmt, ...) do { errmsg(fmt ": %m", ## __VA_ARGS__); exit(EXIT_FAILURE); } while(0)
#define failure(fmt, ...) do { errmsg(fmt, ## __VA_ARGS__); exit(EXIT_FAILURE); } while(0)

enum {
    REDIS_RDB_6BITLEN = 0,
    REDIS_RDB_14BITLEN = 1,
    REDIS_RDB_32BITLEN = 2,
    REDIS_RDB_ENCVAL = 3,

    REDIS_RDB_OPCODE_AUX = 250,
    REDIS_RDB_OPCODE_RESIZEDB = 251,
    REDIS_RDB_OPCODE_EXPIRETIME_MS = 252,
    REDIS_RDB_OPCODE_EXPIRETIME = 253,
    REDIS_RDB_OPCODE_SELECTDB = 254,
    REDIS_RDB_OPCODE_EOF = 255,

    REDIS_RDB_TYPE_STRING = 0,
    REDIS_RDB_TYPE_LIST = 1,
    REDIS_RDB_TYPE_SET = 2,
    REDIS_RDB_TYPE_ZSET = 3,
    REDIS_RDB_TYPE_HASH = 4,
    REDIS_RDB_TYPE_ZSET_2 = 5,
    REDIS_RDB_TYPE_HASH_ZIPMAP = 9,
    REDIS_RDB_TYPE_LIST_ZIPLIST = 10,
    REDIS_RDB_TYPE_SET_INTSET = 11,
    REDIS_RDB_TYPE_ZSET_ZIPLIST = 12,
    REDIS_RDB_TYPE_HASH_ZIPLIST = 13,
    REDIS_RDB_TYPE_LIST_QUICKLIST = 14,

    REDIS_RDB_ENC_INT8 = 0,
    REDIS_RDB_ENC_INT16 = 1,
    REDIS_RDB_ENC_INT32 = 2,
    REDIS_RDB_ENC_LZF = 3
};

/* ------------------------------------------------------------------------- */

enum { FUNNYINT_MAXLEN = 5 };

static int funnyint_parse(const void *b, int len, uint32_t *out, int *special)
{
    errno = EINVAL;

    if(len < 1)
        return -1;

    const uint8_t *buf = b;
    uint32_t x;

    switch((buf[0] >> 6) & 0xff)
    {
        case REDIS_RDB_6BITLEN:
            *out = buf[0] & 0x3f;
            *special = 0;
            return 1;
        case REDIS_RDB_14BITLEN:
            if(len < 2) return -1;
            *out = ((buf[0] & 0x3f) << 8) | (buf[1]);
            *special = 0;
            return 2;
        case REDIS_RDB_32BITLEN:
            if(buf[0] == 0x80) {
                if(len < 5) return -1;
                memcpy(&x, buf+1, 4);
                *out = be32toh(x);
                *special = 0;
                return 5;
            }
            break;
        case REDIS_RDB_ENCVAL:
            *out = buf[0] & 0x3f;
            *special = 1;
            return 1;
    }

    assert("unreachable");
    abort();
}
static int funnyint_peek(struct reader *rd, uint32_t *out, int *special)
{
    ssize_t rc = reader_ahead(rd, FUNNYINT_MAXLEN);
    if(-1 == rc)
        return -1;
    return funnyint_parse(rd->rdptr, rc, out, special);
}
static int funnyint_read(struct reader *rd, uint32_t *out, int *special)
{
    int rc = funnyint_peek(rd, out, special);
    if(-1 == rc)
        return -1;
    reader_advance(rd, rc);
    return rc;
}
static int funnyint_write(struct writer *wr, uint32_t x)
{
    char buf[FUNNYINT_MAXLEN];
    int buflen;

    if(x < 64) {
        buf[0] = (x & 0x3f) | (REDIS_RDB_6BITLEN << 6);
        buflen = 1;
    } else if(x < 16384) {
        buf[0] = (x >> 8) | (REDIS_RDB_14BITLEN << 6);
        buf[1] = (x & 0xff);
        buflen = 2;
    } else {
        buf[0] = REDIS_RDB_32BITLEN;
        x = htobe32(x);
        memcpy(buf+1, &x, 4);
        buflen = 5;
    }

    return writer_write(wr, buf, buflen);
}

/* ------------------------------------------------------------------------- */

typedef int rdb_ver_t;
static inline int rdb_has_checksum(rdb_ver_t ver) {
    return ver >= 5;
}

static inline void rdb_need(struct reader *rd, size_t n, const char *threat)
{
    ssize_t rc = reader_ahead(rd, n);
    if(-1 == rc)
        failerr("reader_ahead");
    if((size_t)rc < n)
        failure("%s: %s", rd->name, threat);
}

static rdb_ver_t rdb_check_header(struct reader *rd)
{
    rdb_need(rd, 9, "not a redis file (too short)");

    if(0 != memcmp(rd->rdptr, "REDIS", 5))
        failure("%s: not a redis file (invalid signature)", rd->name);

    for(int i=5; i<9; i++)
        if(rd->rdptr[i] < '0' || rd->rdptr[i] > '9')
            failure("%s: not a redis file (non-digit in version field)", rd->name);
    char verbuf[5] = { rd->rdptr[5], rd->rdptr[6], rd->rdptr[7], rd->rdptr[8], '\0' };

    reader_advance(rd, 9);

    return strtol(verbuf, NULL, 10);
}
static void rdb_write_header(struct writer *wr, rdb_ver_t ver)
{
    char buf[16];
    int n = sprintf(buf, "REDIS%04d", ver);
    if(-1 == writer_write(wr, buf, n))
        failerr("writer_write");
}

static void rdb_check_crc(struct reader *rd, rdb_ver_t ver)
{
    ssize_t rc = reader_ahead(rd, 9);
    if(-1 == rc) {
        errmsg("%s: failed to verify rdb tail: reader_ahead: %m", rd->name);
        return;
    }

    if(rdb_has_checksum(ver))
    {
        if(rc < 8) {
            errmsg("%s: rdb tail corrupted (missing checksum)", rd->name);
            return;
        }
        reader_advance(rd, 8);
        rc -= 8;
        if(0 != rd->crc64) {
            errmsg("%s: rdb tail corrupted (invalid checksum; residuum: %016lX)", rd->name, rd->crc64);
            return;
        }
    }

    if(rc != 0) {
        errmsg("%s: garbage after rdb tail", rd->name);
        return;
    }
}
static void rdb_write_crc(struct writer *wr)
{
    uint64_t crc = htole64(wr->crc64);
    if(-1 == writer_write(wr, &crc, 8))
        failerr("writer_write");
}

struct rdb_string_fmt {
    int (*xfer)(void *out, const void *in, const struct rdb_string_fmt *fmt);
    uint32_t encbytes, decbytes;
};
static int rdb_string_memcpy(void *out, const void *in, const struct rdb_string_fmt *fmt) {
    memcpy(out, in, fmt->encbytes);
    ((char *)out)[fmt->decbytes] = '\0';
    return 0;
}
static int rdb_string_int8(void *out, const void *in, const struct rdb_string_fmt *fmt) {
    (void)fmt; sprintf(out, "%d", (int)*(int8_t *)in); return 0;
}
static int rdb_string_int16(void *out, const void *in, const struct rdb_string_fmt *fmt) {
    (void)fmt; sprintf(out, "%d", (int)*(int16_t *)in); return 0;
}
static int rdb_string_int32(void *out, const void *in, const struct rdb_string_fmt *fmt) {
    (void)fmt; sprintf(out, "%d", (int)*(int32_t *)in); return 0;
}
static int rdb_string_lzf(void *out, const void *in, const struct rdb_string_fmt *fmt) {
    if(lzf_decompress(in, fmt->encbytes, out, fmt->decbytes) != fmt->decbytes)
        return -1;
    ((char *)out)[fmt->decbytes] = '\0';
    return 0;
}
static void rdb_read_string_header(struct reader *rd, struct rdb_string_fmt *fmt)
{
    uint32_t hdr;
    int special;

    if(-1 == funnyint_read(rd, &hdr, &special))
        failerr("funnyint_read");

    if(!special) {
        fmt->encbytes = hdr;
        fmt->decbytes = hdr;
        fmt->xfer = rdb_string_memcpy;
    } else if(REDIS_RDB_ENC_INT8 == hdr) {
        fmt->encbytes = 1;
        fmt->decbytes = 4; /* "-128" 4 bytes */
        fmt->xfer = rdb_string_int8;
    } else if(REDIS_RDB_ENC_INT16 == hdr) {
        fmt->encbytes = 2;
        fmt->decbytes = 6; /* "-32768" 6 bytes */
        fmt->xfer = rdb_string_int16;
    } else if(REDIS_RDB_ENC_INT32 == hdr) {
        fmt->encbytes = 4;
        fmt->decbytes = 11; /* "-2147483648" 11 bytes */
        fmt->xfer = rdb_string_int32;
    }
    else if(REDIS_RDB_ENC_LZF == hdr)
    {
        if(-1 == funnyint_read(rd, &fmt->encbytes, &special))
            failerr("funnyint_read");
        if(special)
            failure("%s: malformed rdb file (lzf compressed length is a special funnyint)", rd->name);

        if(-1 == funnyint_read(rd, &fmt->decbytes, &special))
            failerr("funnyint_read");
        if(special)
            failure("%s: malformed rdb file (lzf uncompressed length is a special funnyint)", rd->name);

        fmt->xfer = rdb_string_lzf;
    }
    else
        failure("%s: malformed rdb file (unknown string storage method)", rd->name);
}

static int rdb_read_string(struct reader *rd, char **bufp, size_t *buflenp)
{
    struct rdb_string_fmt fmt;
    rdb_read_string_header(rd, &fmt);

    char *buf = *bufp;
    size_t buflen = *buflenp;

    if(buflen < fmt.decbytes+1)
    {
        buflen = (fmt.decbytes+1 < 2*buflen) ? 2*buflen : fmt.decbytes+1;

        buf = realloc(buf, buflen);
        if(NULL == buf)
            failerr("realloc");

        *bufp = buf;
        *buflenp = buflen;
    }

    rdb_need(rd, fmt.encbytes, "truncated rdb file (string data not long enough)");
    fmt.xfer(buf, rd->rdptr, &fmt);
    reader_advance(rd, fmt.encbytes);

    return fmt.decbytes;
}

static int rdb_read_dbsel(struct reader *rd)
{
    while(1) {
        rdb_need(rd, 1, "truncated file (expected db selector or eof)");
        uint8_t opcode = (uint8_t)rd->rdptr[0];
        reader_advance(rd, 1);

        if(REDIS_RDB_OPCODE_EOF == opcode)
            return -1;

        if(REDIS_RDB_OPCODE_AUX == opcode) {
            struct rdb_string_fmt fmt;

            rdb_read_string_header(rd, &fmt);
            reader_advance(rd, fmt.encbytes);

            rdb_read_string_header(rd, &fmt);
            reader_advance(rd, fmt.encbytes);
            continue;
        }

        if(REDIS_RDB_OPCODE_SELECTDB == opcode) {
            uint32_t dbnum;
            int special;
            if(-1 == funnyint_read(rd, &dbnum, &special))
                failerr("%s: malformed db index", rd->name);
            if(special)
                failure("%s: db index is a special funnyint", rd->name);
            return dbnum;
        }

        failure("%s: malformed file (expected db selector or eof, got: %d)", rd->name, opcode);
    }
}
static void rdb_write_dbsel(struct writer *wr, int dbnum)
{
    char buf[1];
    if(-1 != dbnum)
        buf[0] = REDIS_RDB_OPCODE_SELECTDB;
    else
        buf[0] = REDIS_RDB_OPCODE_EOF;

    if(-1 == writer_write(wr, buf, 1))
        failerr("writer_write");

    if(-1 != dbnum)
        if(-1 == funnyint_write(wr, dbnum))
            failerr("funnyint_write");
}

/* ------------------------------------------------------------------------- */

/* forward decls of some utilities not directly related to sharding process */
static void fmt_filesize(char *buf, off_t size);

static inline int is_quiet();

static void start_progress_timer();
static inline int need_progress_update();
static void stop_progress_timer();

struct shard_ctx
{
    hashfn_t hfn;
    shardfn_t sfn;

    regex_t * const * exclude;
    int exclude_count;

    int rd_count, wr_count;
    struct reader *rd;
    struct writer *wr;

    off_t total_size;
    time_t start_time;

    char *keybuf;
    size_t keybuflen;
};

static void shard_progress_update(struct shard_ctx *ctx)
{
    off_t processed_size = 0;
    for(int i=0; i<ctx->rd_count; i++)
        processed_size += ctx->rd[i].processed_size;
    off_t remaining_size = ctx->total_size - processed_size;

    float percent = 100.f * (float)processed_size / (float)ctx->total_size;

    time_t now = time(NULL);
    int elapsed = now - ctx->start_time;

    char total_buf[16], processed_buf[16], rate_buf[16];
    fmt_filesize(total_buf, ctx->total_size);
    fmt_filesize(processed_buf, processed_size);

    printf("\033[K%6.2f%% done; processed %s of %s; elapsed time %02dm%02ds",
           percent, processed_buf, total_buf, elapsed / 60, elapsed % 60);

    if(processed_size > 0 && elapsed > 0)
    {
        int eta = (float)remaining_size / (float)processed_size * (float)elapsed;
        fmt_filesize(rate_buf, processed_size / elapsed);
        printf("; %s/sec; eta %02dm%02ds", rate_buf, eta / 60, eta % 60);
    }

    putchar('\r');
    fflush(stdout);
}

static int shard_read_opcode(struct reader *rd)
{
    int got_expiry_sec = 0, got_expiry_msec = 0;

    for(;;)
    {
        rdb_need(rd, 1, "truncated rdb file (expected opcode or object type)");
        uint8_t opcode = rd->rdptr[0];

        if(REDIS_RDB_OPCODE_SELECTDB == opcode ||
           REDIS_RDB_OPCODE_EOF == opcode)
            return opcode;

        reader_advance(rd, 1);

        if(REDIS_RDB_OPCODE_EXPIRETIME_MS == opcode)
        {
            if(got_expiry_msec)
                failure("%s: malformed rdb file (repeated REDIS_RDB_OPCODE_EXPIRETIME_MS)", rd->name);

            rdb_need(rd, 8, "truncated rdb file (expected expiry msec timestamp)");
            reader_advance(rd, 8);
            got_expiry_msec = 1;
            continue;
        }

        if(REDIS_RDB_OPCODE_EXPIRETIME == opcode)
        {
            if(got_expiry_sec)
                failure("%s: malformed rdb file (repeated REDIS_RDB_OPCODE_EXPIRETIME)", rd->name);

            rdb_need(rd, 4, "truncated rdb file (expected expiry timestamp)");
            reader_advance(rd, 4);
            got_expiry_sec = 1;
            continue;
        }

        if(REDIS_RDB_OPCODE_RESIZEDB == opcode) {
            uint32_t val;
            int special;

            if(-1 == funnyint_read(rd, &val, &special))
                failerr("funnyint_read");
            if(special)
                failure("%s: malformed rdb file (db size is a special funnyint)", rd->name);
            if(-1 == funnyint_read(rd, &val, &special))
                failerr("funnyint_read");
            if(special)
                failure("%s: malformed rdb file (expires size is a special funnyint)", rd->name);
            continue;
        }

        return opcode;
    }
}

static void shard_xfer(struct reader *rd, struct writer *wr, int opcode)
{
    uint32_t stringcnt, mult = 1;
    int special;

    switch(opcode)
    {
        case REDIS_RDB_TYPE_STRING:
        case REDIS_RDB_TYPE_HASH_ZIPMAP:
        case REDIS_RDB_TYPE_LIST_ZIPLIST:
        case REDIS_RDB_TYPE_SET_INTSET:
        case REDIS_RDB_TYPE_ZSET_ZIPLIST:
        case REDIS_RDB_TYPE_HASH_ZIPLIST:
            stringcnt = 1;
            break;

        case REDIS_RDB_TYPE_ZSET:
        case REDIS_RDB_TYPE_HASH:
            mult = 2;
            __attribute__ ((fallthrough));
        case REDIS_RDB_TYPE_LIST:
        case REDIS_RDB_TYPE_SET:
        case REDIS_RDB_TYPE_LIST_QUICKLIST:
        case REDIS_RDB_TYPE_ZSET_2:
            reader_pin(rd);
            if(-1 == funnyint_read(rd, &stringcnt, &special))
                failerr("funnyint_read");
            if(special)
                failure("%s: malformed rdb file (string count is a special funnyint)", rd->name);
            if(-1 == xfer_pinned(rd, wr))
                failerr("xfer_pinned");
            stringcnt *= mult;
            break;

        default:
            failure("%s: malformed rdb file (unsupported object type %d)", rd->name, opcode);
    }

    while(stringcnt-- > 0)
    {
        struct rdb_string_fmt fmt;

        reader_pin(rd);
        rdb_read_string_header(rd, &fmt);
        if(-1 == xfer_pinned(rd, wr))
            failerr("xfer_pinned");

        ssize_t rc = xfer_bytes(rd, wr, fmt.encbytes);
        if(-1 == rc)
            failerr("xfer_bytes");
        if((size_t)rc != fmt.encbytes)
            failure("%s: truncated rdb file (object data)", rd->name);

        if(opcode == REDIS_RDB_TYPE_ZSET_2) {
            rc = xfer_bytes(rd, wr, 8);
            if(-1 == rc)
                failerr("xfer_bytes");
            if((size_t)rc != 8)
                failure("%s: truncated rdb file (object data)", rd->name);
        }
    }
}

static void shard_one(struct shard_ctx *ctx, struct reader *rd)
{
    for(;;)
    {
        if(need_progress_update())
            shard_progress_update(ctx);

        reader_pin(rd);

        int opcode = shard_read_opcode(rd);

        if(REDIS_RDB_OPCODE_SELECTDB == opcode ||
           REDIS_RDB_OPCODE_EOF == opcode) {
            reader_unpin(rd);
            break;
        }

        int keylen = rdb_read_string(rd, &ctx->keybuf, &ctx->keybuflen);

        hash_t hash = hashfn_hash(ctx->hfn, ctx->keybuf, keylen);
        int shardidx = shardfn_dispatch(ctx->sfn, hash);

        struct writer *wr = &ctx->wr[shardidx];

        for(int i=0; i<ctx->exclude_count; i++)
            if(0 == regexec(ctx->exclude[i], ctx->keybuf, 0,NULL, 0)) {
                wr->mute = 1;
                break;
            }

        if(-1 == xfer_pinned(rd, wr))
            failerr("xfer_pinned");
        shard_xfer(rd, wr, opcode);

        wr->mute = 0;
    }
}

static void shard(struct shard_ctx *ctx)
{
    rdb_ver_t ver[ctx->rd_count],
              maxver = 0;

    ctx->total_size = 0;

    for(int i=0; i<ctx->rd_count; i++)
    {
        ver[i] = rdb_check_header(&ctx->rd[i]);
        if(ver[i] > 9)
            failure("%s: rdb file version %d is not supported", ctx->rd[i].name, ver[i]);
        if(ver[i] > maxver)
            maxver = ver[i];
        ctx->total_size += ctx->rd[i].total_size;
    }

    if(!is_quiet())
    {
        char totalsize[16];
        fmt_filesize(totalsize, ctx->total_size);
        printf("%d input rdbs (%s); %d shards; hash %s; sharder %s; rdb version %d\n",
                ctx->rd_count, totalsize, ctx->wr_count,
                hashfn_name(ctx->hfn), shardfn_name(ctx->sfn),
                maxver);

        ctx->start_time = time(NULL);

        start_progress_timer();
        shard_progress_update(ctx);
    }

    int crc_enable = rdb_has_checksum(maxver);
    for(int i=0; i<ctx->wr_count; i++) {
        ctx->wr[i].crc_enable = crc_enable;
        rdb_write_header(&ctx->wr[i], maxver);
    }

    int db_ahead[ctx->rd_count];
    for(int i=0; i<ctx->rd_count; i++)
        db_ahead[i] = rdb_read_dbsel(&ctx->rd[i]);

    ctx->keybuf = NULL;
    ctx->keybuflen = 0;

    for(;;)
    {
        int min_db = 0x7fffffff;
        for(int i=0; i<ctx->rd_count; i++)
            if(-1 != db_ahead[i] && min_db > db_ahead[i])
                min_db = db_ahead[i];

        if(0x7fffffff == min_db)
            break;

        for(int i=0; i<ctx->wr_count; i++)
            rdb_write_dbsel(&ctx->wr[i], min_db);

        for(int i=0; i<ctx->rd_count; i++)
            if(db_ahead[i] == min_db) {
                shard_one(ctx, &ctx->rd[i]);
                db_ahead[i] = rdb_read_dbsel(&ctx->rd[i]);
            }
    }

    free(ctx->keybuf);

    for(int i=0; i<ctx->rd_count; i++)
        rdb_check_crc(&ctx->rd[i], ver[i]);

    for(int i=0; i<ctx->wr_count; i++)
    {
        rdb_write_dbsel(&ctx->wr[i], -1);
        if(crc_enable)
            rdb_write_crc(&ctx->wr[i]);
        writer_flush(&ctx->wr[i]);
    }

    if(!is_quiet()) {
        shard_progress_update(ctx);
        stop_progress_timer();
        printf("\ncompleted successfully.\n");
    }
}

/* ------------------------------------------------------------------------- */

static int quiet = 0;
static inline int is_quiet() {
    return quiet;
}

static void fmt_filesize(char *buf, off_t size)
{
    if(size < 10000)
        sprintf(buf, "%llu B", (unsigned long long)size);
    else if(size < 1048576)
        sprintf(buf, "%llu KB", (unsigned long long)size / 1024ULL);
    else if(size < 100 * 1048576)
        sprintf(buf, "%.2lf MB", (double)size / 1048576.);
    else if(size < 1073741824)
        sprintf(buf, "%.1lf MB", (double)size / 1048576.);
    else
        sprintf(buf, "%.2lf GB", (double)size / 1073741824.);
}


static volatile int progress_update_flag;

static void progress_timer_fn(int sig) {
    (void) sig;
    progress_update_flag = 1;
    alarm(1);
}
static void start_progress_timer()
{
    struct sigaction sa;
    sa.sa_handler = progress_timer_fn;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_restorer = NULL;

    if(-1 == sigaction(SIGALRM, &sa, NULL))
        errmsg("sigaction(SIGALRM): %m");

    alarm(1);
}
static inline int need_progress_update()
{
    int x = progress_update_flag;
    progress_update_flag = 0;
    return x;
}
static void stop_progress_timer()
{
    alarm(0);

    struct sigaction sa;
    sa.sa_handler = SIG_DFL;
    sa.sa_sigaction = NULL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_restorer = NULL;

    if(-1 == sigaction(SIGALRM, &sa, NULL))
        errmsg("sigaction(SIGALRM): %m");

    progress_update_flag = 0;
}

static void print_usage() __attribute__ ((noreturn));
static void print_usage()
{
    fputs("Usage: rdbshard [options] -i input1.rdb input2.rdb ... -o shard1 shard2 ...\n"
          "\n"
          "rdbshard performs twemproxy (aka. nutcracker)-compatible sharding directly\n"
          "on Redis dump files. Multiple input files and output shards can be specified\n"
          "after -i and -o options respectively. Shards will be saved to files\n"
          "[shardname].rdb, which must not exist. Please note that shard names must be\n"
          "exactly the same as in twemproxy configuration.\n"
          "\n"
          "Options:\n"
          "    -q            quiet operation (no progress bar etc)\n"
          "    -h [hashfn]   select hash\n"
          "    -s [shardfn]  select sharder\n"
          "    -x [regexp]   exclude keys matching given posix extended regexp\n",
          stderr);

    fputs("available hashes [-h] (* is default): ", stderr);
    for(int i=0; all_hashfns[i]; i++)
        fprintf(stderr, " %s%s",
                default_hashfn == all_hashfns[i] ? "*" : "",
                all_hashfns[i]->name);

    fputs("\navailable sharders [-s] (* is default): ", stderr);
    for(int i=0; all_shardfns[i]; i++)
        fprintf(stderr, " %s%s",
                default_shardfn == all_shardfns[i] ? "*" : "",
                all_shardfns[i]->name);

    fputs("\n", stderr);
    exit(EXIT_FAILURE);
}

static regex_t *compile_regex(const char *str)
{
    regex_t *ret = malloc(sizeof(regex_t));
    if(NULL == ret)
        failerr("malloc");

    int rc = regcomp(ret, str, REG_NOSUB | REG_EXTENDED);
    if(0 == rc)
        return ret;

    char errbuf[128];
    regerror(rc, ret, errbuf, sizeof(errbuf));
    failure("failed to compile -x regexp: %s", errbuf);
}

static void free_regex(regex_t *re) {
    free(re);
}

int main(int argc, char *argv[])
{
    const char *input_filenames[argc],
               *node_names[argc];
    regex_t *exclude_regexs[argc];

    int n_inputs = 0,
        n_nodes = 0,
        n_excludes = 0;

    const char *sel_hashfn = default_hashfn->name,
               *sel_shardfn = default_shardfn->name;

    int opt, io_opt = '?';
    while((opt = getopt(argc, argv, "-qh:s:x:io")) != -1)
    {
        if('i' == opt || 'o' == opt) {
            io_opt = opt;
            continue;
        }
        if(1 == opt)
            opt = io_opt;
        else
            io_opt = '?';

        switch(opt) {
            case 'q': quiet = 1; break;
            case 'h': sel_hashfn = optarg; break;
            case 's': sel_shardfn = optarg; break;
            case 'x': exclude_regexs[n_excludes++] = compile_regex(optarg); break;
            case 'i': input_filenames[n_inputs++] = optarg; break;
            case 'o': node_names[n_nodes++] = optarg; break;
            default:  print_usage(); break;
        }
    }

    if(0 == n_inputs || 0 == n_nodes)
        print_usage();

    struct shard_ctx ctx;

    ctx.hfn = hashfn_init(sel_hashfn);
    if(NULL == ctx.hfn) {
        int missing = ENOENT == errno;
        errmsg("failed to initialize hash %s: hashfn_init: %m", sel_hashfn);
        if(missing) print_usage();
        exit(EXIT_FAILURE);
    }

    ctx.sfn = shardfn_init(sel_shardfn, node_names, n_nodes);
    if(NULL == ctx.sfn) {
        int missing = ENOENT == errno;
        errmsg("failed to initialize sharder %s: shardfn_init: %m", sel_shardfn);
        if(missing) print_usage();
        exit(EXIT_FAILURE);
    }

    ctx.exclude = exclude_regexs;
    ctx.exclude_count = n_excludes;

    struct reader rd[n_inputs];
    struct writer wr[n_nodes];
    ctx.rd_count = n_inputs;
    ctx.wr_count = n_nodes;
    ctx.rd = rd;
    ctx.wr = wr;

    for(int i=0; i<n_inputs; i++)
    {
        int fd = open(input_filenames[i], O_RDONLY|O_CLOEXEC);
        if(-1 == fd)
            failerr("failed to open input file %s: open", input_filenames[i]);
        if(-1 == reader_init(&rd[i], fd, input_filenames[i]))
            failerr("reader_init");

        if(-1 == posix_fadvise(fd, 0,0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE | POSIX_FADV_WILLNEED))
            errmsg("posix_fadvise: %m");
    }

    for(int i=0; i<n_nodes; i++)
    {
        int namelen = strlen(node_names[i]);
        char buf[namelen + 8];
        strcpy(buf, node_names[i]);
        strcpy(buf + namelen, ".rdb");

        int fd = open(buf, O_WRONLY|O_EXCL|O_CREAT|O_CLOEXEC, 0666);
        if(-1 == fd)
            failerr("failed to create output file %s: open", buf);
        if(-1 == writer_init(&wr[i], fd))
            failerr("writer_init");
    }

    shard(&ctx);

    for(int i=0; i<n_nodes; i++)
        writer_free(&wr[i]);

    for(int i=0; i<n_inputs; i++) {
        reader_free(&rd[i]);
        close(rd[i].fd);
    }

    for(int i=0; i<n_excludes; i++)
        free_regex(exclude_regexs[i]);

    shardfn_free(ctx.sfn);

    return 0;
}
