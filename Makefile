

# tinycbor
LIBCBOR = tinycbor/lib/libtinycbor.a

INCLUDE = -I./tinycbor/src
INCLUDE += -I./micro-ecc
INCLUDE += -I./include

SOURCE += src/*.c
SOURCE += micro-ecc/*.c

MAIN += src/main/main.c

TEST += src/test/test.c




all: cbor main cose-shared
	
cose-shared:
	$(CC) -Wall -fPIC -c $(SOURCE) $(INCLUDE)
	$(CC) -shared -o lib/libcose.so ./*.o $(LIBCBOR)
	rm ./*.o

main: 
	mkdir -p build && $(CC) -g -o build/main $(SOURCE) $(MAIN) $(LIBCBOR) $(INCLUDE)
	
cbor:
	cd tinycbor/ && $(MAKE) clean && $(MAKE) LDFLAGS='' -j8
	
clean:
	cd tinycbor && $(MAKE) clean && cd .. && rm -rf build	