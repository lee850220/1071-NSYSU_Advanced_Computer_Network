 # ---------------------------------------------INFORMATION--------------------------------------------
 # 	Project Name: Advanced Computer Networking HW2
 #	Author: Kelvin Lee 李冠霖
 #	Version: 1.0
 #	Environment: Linux
 # 	Date: 2018/09/30  :
 # ===================================================================================================*/
SHELL := /bin/bash

.PHONY: clean proc plot

all: clean proc plot

proc:
	@for i in $$(seq 1 2 5);	 																						\
	do																													\
		echo "Processing $${i}_iperf_tcp to $${i}_iperf_tcp_proc";														\
		cat $${i}_iperf_tcp | grep sec | head -n 20 | tr - " " | awk '{print $$4, $$8}' > $${i}_iperf_tcp_proc;			\
		echo "Processing $${i}_iperf_udp to $${i}_iperf_udp_proc";														\
		cat $${i}_iperf_udp | grep sec | head -n 20 | tr - " " | awk '{print $$4, $$8}' > $${i}_iperf_udp_proc;			\
	done

plot:
	gnuplot tcp_script > tcp.png
	gnuplot udp_script > udp.png

clean:
	rm -f *_proc* *p.png
