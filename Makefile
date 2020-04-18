CC      = gcc
CFLAGS  = -D_FILE_OFFSET_BITS=64 -O3 -pthread -lstdc++
OPENSSL_FLAG = -lcrypto
REGEX_FLAG = -lboost_regex
GZIP_FLAG = -lz

all: clean fastdd

fastdd : fastdd.cpp fastdd_t.hpp partition_manager.hpp fastdd_module.hpp fastdd_module_regex.hpp fastdd_module_conv.hpp fastdd_module_gzip.hpp
	$(CC) -o fastdd fastdd.cpp fastdd_t.hpp partition_manager.hpp fastdd_module.hpp fastdd_module_regex.hpp fastdd_module_conv.hpp fastdd_module_gzip.hpp $(CFLAGS) $(OPENSSL_FLAG) $(REGEX_FLAG) $(GZIP_FLAG)

clean :
	rm -f *.o fastdd
