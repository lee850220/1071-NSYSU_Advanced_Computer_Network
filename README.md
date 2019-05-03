# 1071-NSYSU_Advanced_Computer_Network
This is the homework of the course.

## Part 1. Web Browsing (DNS, TCP)  

**Objective**  
In this exercise we analyze the layered structure of network protocols using a web browsing example. We examine the header structure of the PDUs at the data link, IP, transport, and application layers. In particular we observe how addresses and port numbers work together to enable end-to-end applications.

**Procedure**  
Read [2018 Advanced Computer Networks Homework 1.pdf](https://github.com/lee850220/1071-NSYSU_Advanced_Computer_Network/blob/master/HW1/2018%20Advanced%20Computer%20Networks%20Homework%201.pdf "2018 Advanced Computer Networks Homework 1.pdf") in detail. 

## Part 2. Probing the Internet (ICMP, PING, Traceroute)

**Objective**  
In this exercise we investigate two applications of the Internet Control Message
Protocol (ICMP):
1. PING uses ICMP to determine whether a host is reachable
2. Traceroute uses ICMP to allow users to determine the route that an IP packettakes from a local host to a remote host

**Protocols Examined**    
- ICMP: Echo, Echo Reply, Time Exceeded messages  
- IP Time-to-Live  
- PING application  
- Traceroute application

**Background Material**  
PING, Traceroute commands: Consult your system documentation for information on
using these commands. (In Ubuntu: man ping or man traceroute)