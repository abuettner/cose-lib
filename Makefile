

# tinycbor
LIB = -L./tinycbor/lib
LIB += -L./mbedtls/library

INCLUDE = -I./tinycbor/src
INCLUDE += -I./micro-ecc
INCLUDE += -I./mbedtls/include
INCLUDE += -I./include

SOURCE += src/*.c
SOURCE += micro-ecc/*.c

TEST += src/test/test.c




all: lib-cbor lib-mbedtls examples/* #lib-cose
	
lib-cose:
	$(CC) -Wall -fPIC -c $(SOURCE) $(INCLUDE)
	$(CC) -shared -o lib/libcose.so ./*.o $(LIB) -ltinycbor -lmbedcrypto
	rm ./*.o


lib-cbor:
	cd tinycbor/ && $(MAKE) clean && $(MAKE) LDFLAGS='' -j8 lib/libtinycbor.a

lib-mbedtls:
	cd mbedtls/ && $(MAKE) lib

examples: examples/sign1 examples/encrypt0 examples/encrypt examples/cosekey

examples/sign1: 
	mkdir -p build/examples && $(CC) -g -o build/examples/sign1 examples/sign1.c $(SOURCE) $(LIB) $(INCLUDE) -ltinycbor -lmbedcrypto

examples/encrypt0: 
	mkdir -p build/examples && $(CC) -g -o build/examples/encrypt0 examples/encrypt0.c $(SOURCE) $(LIB) $(INCLUDE) -ltinycbor -lmbedcrypto

examples/encrypt: 
	mkdir -p build/examples && $(CC) -g -o build/examples/encrypt examples/encrypt.c $(SOURCE) $(LIB) $(INCLUDE) -ltinycbor -lmbedcrypto

examples/cosekey: 
	mkdir -p build/examples && $(CC) -g -o build/examples/cosekey examples/cosekey.c $(SOURCE) $(LIB) $(INCLUDE) -ltinycbor -lmbedcrypto


clean:
	cd tinycbor && $(MAKE) clean && cd .. && cd mbedtls && $(MAKE) clean && cd .. && rm -rf build	