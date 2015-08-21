CFLAGS = -g -O2 -std=c99 -Wall -Winit-self -Wmissing-include-dirs -Wextra -Wdeclaration-after-statement -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Waggregate-return -Wmissing-declarations -Wmissing-field-initializers -Wnested-externs -Winvalid-pch -pedantic -pipe -fstack-protector-all

# TODO this one causes a warning from isfinite((double) adouble) :/
#CFLAGS += -Wconversion

CFLAGS += -Werror

diversion: diversion.c diversion.h

clean:
	@-rm -f diversion *.core 2>/dev/null
