/* $Id$ */
/*
 * Copyright (c) 2003-2004 Jose Nazario <jose@monkey.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Jose Nazario.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * thanks for patches:
 * Jean-Francois Brousseau, Ron Rosson, Gustavo, Michael Coulter, Joris Vink
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include <curses.h>
#include <pcap.h>
#include <dnet.h>

#include "pcaputil.h"

int             pcap_off, use_color = 0;
rand_t         *rand_pos;
WINDOW         *win;

void           	matrix_restart(int sig);
void 		usage(char *progname);
char *		inet_ntoasc(ip_addr_t in);
void 		printline(char *line, unsigned int len);
void 		grab_packets(u_char * u, const struct pcap_pkthdr * pkthdr, const u_char * pkt);
void 		init_curses(void);

void
usage(char *progname)
{
	printf("usage: %s [-c] -i intf | file [filter]\n", progname);
	printf("\t-c: attempt use colors in output\n");
	printf("\tinput can be a pcap savefile or a network interface\n");
	printf("\tfilter is a pcap filter expression (only TCP, UDP, ICMP used)\n");
	exit(1);
}

/* stolen from openbsd libc, needed my own type */

char           *
inet_ntoasc(ip_addr_t in)
{
	static char     b[18];
	register char  *p;

	p = (char *) &in;
#define UC(b)        (((int)b)&0xff)
	(void) snprintf(b, sizeof(b),
		     "%u.%u.%u.%u", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);
}

/*
 * printline() takes a line to print as a vertical line using a curses
 * window. what it does is pick a random column (vert) and then a random
 * row to start in (hor) and then walks down the column printing a 
 * character at a time. the leading character is bolded to give it that
 * matrix like effect of priting a character.
 */

void
printline(char *line, unsigned int len)
{
	unsigned int    i = 0, hor, hor_orig, vert, blank = 0, height;

	if (line == NULL)
		return;

	vert = rand_uint8(rand_pos) % COLS - 1;	/* X position */
	hor = rand_uint8(rand_pos) % LINES/4;	/* Y position */
	blank = rand_uint8(rand_pos) % 7;	/* do we blank above? */
	if (blank == 1)
		height = (rand_uint8(rand_pos) % (int)(LINES/6) + 3);
	hor_orig = hor;
	move(hor, vert);
	if (use_color)
		 attrset(COLOR_PAIR(COLOR_GREEN));
	for (; i < len; i++) {
		move(hor, vert);
		addch(line[i] | A_BOLD);
		move(hor, vert);
		refresh();
		wrefresh(win);
		usleep(20000);
		addch(line[i] | A_NORMAL);
		refresh();
		wrefresh(win);
		if (blank) {
			move(hor - height, vert);
			addch(32);
			refresh();
			wrefresh(win);
		}
		move(hor, vert);
		if (hor >= LINES - 1)  {
			break;
		} else
			hor++;
	}
	// move(COLS/2, LINES);
	if ((hor >= LINES - 1) && (30 > vert))
		printw("\n");
	refresh();
	wrefresh(win);
	return;
}

/* 
 * pcap callback. we only deal with TCP, UDP and ICMP. we print the
 * src ip and dst ip, ports (or type/code combo) and then hand it off to
 * printline() for display.
 */

void
grab_packets(u_char * u, const struct pcap_pkthdr * pkthdr, const u_char * pkt)
{
	struct eth_hdr *eth;
	struct ip_hdr  *ip;
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;
	struct icmp_hdr *icmp;
	char            line[1024], *srcip, *dstip;

	if (pkt == NULL)
		return;

	eth = (struct eth_hdr *) pkt;
	if (ntohs(eth->eth_type) != ETH_TYPE_IP)
		return;

	ip = (struct ip_hdr *)(pkt + pcap_off);
	if (ip->ip_v != 4)
		return;

	bzero(line, sizeof(line));

	srcip = inet_ntoasc(ip->ip_src);
	dstip = inet_ntoasc(ip->ip_dst); 

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		if (ntohs(ip->ip_len) < 40)
			return;
		tcp = (struct tcp_hdr *)(ip + ntohs(ip->ip_len));
#if 0
		if (!(tcp) || !(tcp->th_sport) || !(tcp->th_dport))
			return;
#endif
		snprintf(line, sizeof(line), "TCP: %s.%d | %s.%d  ",
			 srcip, ntohs(tcp->th_sport),
			 dstip, ntohs(tcp->th_dport));
		break;
	case IPPROTO_UDP:
		udp = (struct udp_hdr *)(ip + IP_HDR_LEN);
		snprintf(line, sizeof(line), "UDP: %s.%d | %s.%d  ",
			 srcip, ntohs(udp->uh_sport),
			 dstip, ntohs(udp->uh_dport));
		break;
	case IPPROTO_ICMP:
		icmp = (struct icmp_hdr *)(ip + IP_HDR_LEN);
		snprintf(line, sizeof(line), "ICMP: %s | %s %d/%d  ",
			 srcip, dstip,
			 ntohs(icmp->icmp_type), ntohs(icmp->icmp_code));
		break;
	default:
		return;
		break;
	}
	printline(line, strlen(line));
	return;
}

/* initialize the curses setup, return a pointer to a curses WINDOW. */

void
init_curses(void)
{
	win = initscr();
	start_color();
	init_pair(COLOR_GREEN, COLOR_GREEN, COLOR_BLACK);
	cbreak();
	werase(win);
	wclear(win);
	scrollok(win, TRUE);
	printline(" ", 1);
}

/*
 * matrixdump is a small program designed to display network traffic
 * in a manner that looks sort of like the matrix view from the movie.
 * it uses pcap and ncurses to achieve this.
 */

int
main(int argc, char *argv[])
{
	pcap_t         *p = NULL;
	char	       *filter, *intf;
	int		c;

        intf = NULL;

	while ((c = getopt(argc, argv, "ci:")) != -1) {
		switch(c) {
		case 'c':
			use_color = 1;
			break;
		case 'i':
			intf = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}	
	}
        argc -= optind;
        argv += optind;

        filter = copy_argv(argv);

	p = pcap_open(intf, 1, 1500);
	if (p == NULL)
		errx(1, "pcap_open() failed");
	if (filter != NULL)
		pcap_filter(p, filter);
	pcap_off = pcap_dloff(p);

	/* revoke privs */
        seteuid(getuid());
        setuid(getuid());
	setegid(getgid());
	setgid(getgid());

	rand_pos = rand_open();

	signal(SIGWINCH, matrix_restart);

	init_curses();

	/* main event loop, driven by pcap */
	pcap_loop(p, -1, grab_packets, (void *) win);

	/* cleanup */
	clrtobot();
	endwin();

	if (p)
		pcap_close(p);

	return (1);
}

void
matrix_restart(int sig)
{
	switch(sig) {
	case SIGWINCH:
       		endwin();
       		win = initscr();
       		start_color();
       		init_pair(COLOR_GREEN, COLOR_GREEN, COLOR_BLACK);
       		cbreak();
       		werase(win);
       		wclear(win);
       		scrollok(win, TRUE);
		break;
	}
}

