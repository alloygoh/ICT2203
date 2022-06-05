PROXY_SERVER = "10.0.0.10:8080"

default: resource
	i686-w64-mingw32-gcc main.c -lcrypt32 -lshell32 resource.o -D'PROXY_SERVER=$(PROXY_SERVER)'

resource:
	i686-w64-mingw32-windres resource.rc resource.o

clean:
	rm ./a.exe resource.o
