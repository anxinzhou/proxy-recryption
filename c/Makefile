CCFLAGS=-I/
all: proxy libproxy
proxy: proxy.h
	gcc -c proxy.c -I /Users/anxin/.local/include/pbc 
	gcc -o proxy proxy.o -L /Users/anxin/.local/lib -lgmp -lpbc
libproxy: proxy 
	gcc -o libproxy.so  -shared -lgmp -lpbc proxy.o
