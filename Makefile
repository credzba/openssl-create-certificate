PROG=mkcert
#CPP=g++
CPP=clang++
CPPFLAGS=-Wall
CFLAGS=-g
INCLUDES=-I/usr/include/boost -I/usr/local/include/clang
LIBS=-L/usr/lib -lboost_system -lboost_program_options -lboost_regex  -lpthread  -L/usr/lib/x86_64-linux-gnu/ \
	-lssl -lcrypto

%.o : %.cpp
	$(CPP) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(PROG): $(PROG).o
	$(CPP) $< -o $@ $(LIBS)

.PHONY: clean
clean:
	@rm -f *.o
	@rm -f $(PROG)

