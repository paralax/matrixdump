matrixdump is just a little PoC (and PoS) program i wrote in an evening to toy with ncurses and demo how you can drive a "matrix" like view using network data. i'm surprised no one's done this before, but it's been on my mind since the original movie came out.

matrixdump isn't as feature rich as tcpdump or tethereal, and the decodes are minimal. just the protocol, IPs, ports ... nothing else. the decodes could definitely be more interesting if you wanted to make them more usable.

amusingly, i'm not a huge fan of the movies, they were ok but the sequels don't get me as turned on as the original.

anyhow, why not drive some fun with a tool like this? part of this is me thinking about how to visualize CTF competitions, and part of it was me delving into the world of ncurses.

what's very funny is that this shows how lousy this interface is for actually looking at data. then again, you can say things like "porn, porn, SYN flood, porn ..."

matrixdump contains code from dugsong's dsniff (the pcaputil routines).

## BUGS ##

matrixdump is just a toy, and isn't very feature filled or stable.
  * the scrolling is a bit wonky at times, but generall works.
  * the color stuff is a bit wonky, set your term to "ansi" on some systems to get it to respect "-c".

## INSTALLATION ##

built and tested on openbsd and OS X. it uses pcap, libdnet, and ncurses. you'll have to tweak a few things for other platforms probably.

## THANKS ##

Jean-Francois Brousseau, Ron Rosson, Gustavo, Michael Coulter, Joris Vink