CC := gcc
CPPFLAGS := -D_FILE_OFFSET_BITS=64 
CFLAGS := -std=c99 -O2 -Wall -Wshadow -Wextra

rdbshard: rdbshard.c md5.c crc64.c lzf_d.c

