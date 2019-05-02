 # ---------------------------------------------INFORMATION--------------------------------------------
 # 	Project Name: Advanced Computer Networking HW5
 #	Author: Kelvin Lee 李冠霖
 #	Version: 1.0
 #	Environment: Linux
 # 	Date: 2018//  :
 # ===================================================================================================*/
SHELL := /bin/bash
CFLAGS := -g -Wall
CC = gcc
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
EXE = ipscanner
EXE2 = $(OBJ:.o=.exe)
NORMAL = \033[0m
RED = \033[1;31m
YELLOW = \033[1;33m
WHITE = \033[1;37m

.PHONY: clean test dep main help changelog check

all: clean dep main

dep:
	@touch .depend
	@echo creating dependency file...
	@for n in $(SRC); do \
		$(CC) $(CFLAGS) -E -MM $$n >> .depend; \
	done
-include .depend

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

main: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -lpcap -lm -o ipscanner

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
