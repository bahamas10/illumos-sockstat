CC ?= cc
CFLAGS = -Wall -DNDEBUG

sockstat: sockstat.c mib.o proc_info.o
	$(CC) $(CFLAGS) -lproc -lsocket -lnsl $^ -o $@

mib.o: mib.c mib.h
	$(CC) $(CFLAGS) -c $< -o $@

proc_info.o: proc_info.c proc_info.h
	$(CC) $(CFLAGS) -lproc -c $< -o $@

.PHONY: clean
clean:
	rm -f sockstat mib.o proc_info.o
