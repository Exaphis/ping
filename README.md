# ping
Toy implementation of the ping command in C.

## Usage

```
$ gcc -Wall -Werror -o ping ping.c
$ sudo ./ping
usage: ping [-6] [-c count] [-t ttl] [-i interval] host

-6           Use IPv6 instead of IPv4
-c count     Stop after sending count ECHO_REQUEST packets
-t ttl       Set the IP Time to Live
-i interval  Wait <interval> seconds between sending each packet
```

