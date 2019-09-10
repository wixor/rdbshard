CC := gcc
CPPFLAGS := -D_FILE_OFFSET_BITS=64
CFLAGS := -std=c99 -O2 -Wall -Wshadow -Wextra

rdbshard: rdbshard.o md5.o crc64.o lzf_d.o

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

clean:
	rm -rf rdbshard *.o
