CC      = gcc
CFLAGS  = -D_FILE_OFFSET_BITS=64 -O3 -pthread -lssl
REGEX_FLAG = -lboost_regex
GZIP_FLAG = -lz

all: clean fastdd

fastdd : fastdd.cpp fastdd_t.hpp partition_manager.hpp fastdd_module.hpp fastdd_module_regex.hpp fastdd_module_conv.hpp fastdd_module_gzip.hpp
	$(CC) -o fastdd $(CFLAGS) $(REGEX_FLAG) $(GZIP_FLAG) fastdd.cpp fastdd_t.hpp partition_manager.hpp fastdd_module.hpp fastdd_module_regex.hpp fastdd_module_conv.hpp fastdd_module_gzip.hpp

clean :
	rm -f *.o fastdd
