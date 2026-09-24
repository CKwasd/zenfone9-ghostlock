CC ?= aarch64-linux-android31-clang
CFLAGS ?= -static -O2 -DZF9_DEVICE -Isrc -pthread

SRCS = src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/persist.c \
       src/prop.c src/cfi.c src/qmain.c src/seqoverlay.c

slide_dev: $(SRCS) src/common.h src/target.h src/offset.h
	$(CC) $(CFLAGS) $(SRCS) -o slide_dev

clean:
	rm -f slide_dev

.PHONY: clean
