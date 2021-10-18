

# tinycbor
LIBCBOR = tinycbor/lib/libtinycbor.a

INCLUDE = -I./tinycbor/src
INCLUDE += -I./micro-ecc
INCLUDE += -I./include

SOURCE += src/*.c
SOURCE += micro-ecc/*.c




all: cbor cose-lib
	

cose-lib: 
	mkdir -p build && $(CC) -g -o build/cose-lib $(SOURCE) $(LIBCBOR) $(INCLUDE)
	
cbor:
	cd tinycbor/ && $(MAKE) clean && $(MAKE) LDFLAGS='' -j8
	
clean:
	cd tinycbor && $(MAKE) clean && cd .. && rm -rf build	