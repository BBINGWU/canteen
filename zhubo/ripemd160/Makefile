# CBMC_GC = ../../bin/cbmc-gc

# .PHONY: all clean

# all: ripemd160.txt

# ripemd160.txt: main.c
# 	$(CBMC_GC) main.c --outfile ripemd160.txt --minimization-time-limit 10

# clean:
# 	rm -f ripemd160.txt

CBMC_GC = ../../bin/cbmc-gc

.PHONY: all clean

all: ripemd160_bristol.txt

ripemd160_bristol.txt: main.c
	# $(CBMC_GC) main.c --format bristol --outfile ripemd160_bristol.txt --minimization-time-limit 10
	$(CBMC_GC) main.c --format bristol --outfile ripemd160.txt --minimization-time-limit 10


clean:
	rm -f ripemd160_bristol.txt
