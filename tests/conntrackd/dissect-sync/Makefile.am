include $(top_srcdir)/Make_global.am

check_PROGRAMS = dissect

dissect_SOURCES = proto.c			\
		  l3_ipv4.c			\
		  l4_tcp.c			\
		  l4_udp.c			\
		  parse.c			\
		  main.c

dissect_LDFLAGS = -dynamic 			\
		  -lpcap
