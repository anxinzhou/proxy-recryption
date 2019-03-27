CCFLAGS=-I/
all: proxy libproxy
proxy: proxy.h
	gcc -c proxy.c -I /usr/local/include/pbc
	gcc -o proxy proxy.o  -lgmp -lpbc
libproxy: proxy 
	gcc -o libproxy.so  -shared -lgmp -lpbc proxy.o
