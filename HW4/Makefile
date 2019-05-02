 # ---------------------------------------------INFORMATION--------------------------------------------
 # 	Project Name: Advanced Computer Networking HW4
 #	Author: Kelvin Lee 李冠霖
 #	Version: 1.3 (beta)
 #	Environment: Linux
 # 	Date: 2018/10/30  19:42
 # ===================================================================================================*/
SHELL := /bin/bash
OSFLAG :=
CFLAGS := -g -Wall
CC = gcc
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
EXE = $(OBJ:.o=)
EXE2 = $(OBJ:.o=.exe)
DEVICE := ens33
NORMAL = \033[0m
RED = \033[1;31m
YELLOW = \033[1;33m
WHITE = \033[1;37m

.PHONY: clean test dep main help changelog check

all: clean dep main

test: clean dep main_test

dep:
	@touch .depend
	@echo creating dependency file...
	@for n in $(SRC); do \
		$(CC) $(CFLAGS) -E -MM $$n >> .depend; \
	done
-include .depend

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

check:

ifdef OS
ifeq ($(OS), Windows_NT)
CFLAGS += -D WIN32
endif
endif

main: check $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -lm -o arp

main_test: CFLAGS += -D DEVICE_NAME=\"$(DEVICE)\"
main_test: main

changelog:
	@echo
	@echo '####--------------------------- ChangeLog ---------------------------####'
	@echo
	@cat ChangeLog.txt
	@echo

help:
	@echo
	@printf 'Please type "$(YELLOW)sudo ./arp -help$(NORMAL)" to get command usage information.\n\n'
	@printf '$(RED)Note:$(NORMAL)\tPlease check your Network Card Interface ID, '
	@printf 'and use "$(YELLOW)make test DEVICE=<your interface ID>$(NORMAL)" to compile.\n'
	@printf '\tIn default settings, use "$(YELLOW)make$(NORMAL)" is "$(WHITE)enp2s0f5$(NORMAL)", '
	@printf 'and use "$(YELLOW)make test$(NORMAL)" is "$(WHITE)ens33$(NORMAL)".\n'
	@echo
	

clean:
	@rm -fv $(OBJ) $(EXE) $(EXE2) .depend

#============================================= Optional =============================================
debug:
	valgrind --leak-check=full ./$(DIR)/$(TEST) > /dev/null 2> res2
	valgrind -v --track-origins=yes --leak-check=full ./$(DIR)/$(TEST) > /dev/null 2> res3
