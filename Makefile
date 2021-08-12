
export V?=0

.PHONY: all
all:
	make -C ta CROSS_COMPILE=$(TA_CROSS_COMPILE)

.PHONY: clean
clean:
	make -C ta clean
	
