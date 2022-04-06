

# tinycbor
LIB = -L./tinycbor/lib
LIB += -L./mbedtls/library

INCLUDE = -I./tinycbor/src
INCLUDE += -I./micro-ecc
INCLUDE += -I./include

SOURCE += src/*.c
SOURCE += micro-ecc/*.c

MAIN += src/main/main.c

TEST += src/test/test.c




all: lib-cbor lib-mbedtls main lib-cose
	
lib-cose:
	$(CC) -Wall -fPIC -c $(SOURCE) $(INCLUDE)
	$(CC) -shared -o lib/libcose.so ./*.o $(LIB) -ltinycbor -lmbedcrypto
	rm ./*.o

main: 
	mkdir -p build && $(CC) -g -o build/main $(SOURCE) $(MAIN) $(LIB) $(INCLUDE) -ltinycbor -lmbedcrypto
	
lib-cbor:
	cd tinycbor/ && $(MAKE) clean && $(MAKE) LDFLAGS='' -j8 lib/libtinycbor.a

lib-mbedtls:
	cd mbedtls/ && $(MAKE) lib

clean:
	cd tinycbor && $(MAKE) clean && cd .. && cd mbedtls && $(MAKE) clean && cd .. && rm -rf build	