

CXX     = g++
CFLAGS  = -g -Wall 
LDFLAGS = -L/usr/lib64/  -L/usr/lib64/openssl
LIBS = -lssl -lcrypto

LOCAL=1

ifeq ($(LOCAL), 1)
INCLUDE += -I/usr/local/ssl/include/ 
endif


all:
	$(CXX) $(INCLUDE) $(CFLAGS) -o tls test_tls.cc  $(LDFLAGS) $(LIBS)


clean:
	rm -f tls
