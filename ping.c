/*
 *  ping.c
 *  Kevin Wu, April 13 2020
 *
 *  A toy implementation of the ping command in C.
 */

#include "ping.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>

/*
 *  get_dest_addresses uses getaddrinfo to resolve the
 *  given host name.
 *  It returns get a linked list of struct addrinfo
 *  that will be passed into socket() and sento().
 */

struct addrinfo* get_dest_addresses(char* destination) {
  struct addrinfo hints = { 0 };

  // why DGRAM? https://echorand.me/posts/my-own-ping
  // opening the socket with SOCK_DGRAM instead of SOCK_RAW
  // avoids using the CAP_NET_RAW capability.
  hints.ai_socktype = SOCK_DGRAM;

  struct addrinfo* address = NULL;
  int status = getaddrinfo(destination, NULL, &hints, &address);
  if (status != 0) {
    fprintf(stderr, "getaddrinfo() failure: %s\n", gai_strerror(status));
    return NULL;
  }

  char ip_addr_str[INET6_ADDRSTRLEN];
  printf("Destination information for %s:\n", destination);

  for (struct addrinfo* addr_ptr = address; addr_ptr != NULL;
       addr_ptr = addr_ptr->ai_next) {
    char* ip_ver = NULL;
    void* sin_addr = NULL;

    if (addr_ptr->ai_family == AF_INET) {
      ip_ver = "IPv4";
      struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr_ptr->ai_addr;
      sin_addr = &ipv4->sin_addr;
    }
    else {
      ip_ver = "IPv6";
      struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr_ptr->ai_addr;
      sin_addr = &ipv6->sin6_addr;
    }

    inet_ntop(addr_ptr->ai_family, sin_addr, ip_addr_str, sizeof(ip_addr_str));

    printf("  %s: %s\n", ip_ver, ip_addr_str);
  }

  return address;
} /* get_dest_addresses() */

/*
 *  send_ping sends an ICMP packet to the given socket
 *  and destination address with the given sequence value.
 *
 *  The function returns the return value of sendto.
 */

int send_ping(int socket_fd, struct addrinfo* dest_addr, int sequence) {
  struct icmphdr icmp_header = { 0 };
  icmp_header.type = ICMP_ECHO;
  icmp_header.un.echo.sequence = sequence;
  // icmp_header.un.echo.id will automatically set.
  // https://lwn.net/Articles/420800/

  int bytes_sent = sendto(socket_fd, &icmp_header, sizeof(icmp_header), 0,
                          dest_addr->ai_addr, dest_addr->ai_addrlen);
  if (bytes_sent == -1) {
    perror("sento() failure");
  }

  return bytes_sent;
} /* send_ping() */

/*
 *  Main function for the ping program.
 */

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("No destination specified.\n");
    return EXIT_FAILURE;
  }

  char* destination = argv[1];

  struct addrinfo* address = get_dest_addresses(destination);
  if (!address) {
    return EXIT_FAILURE;
  }

  // Assume first entry is valid in addrinfo linked list.
  // TODO: walk entire list
  // TODO: IPv4/IPv6 selector?

  int socket_fd = socket(address->ai_family, SOCK_DGRAM, IPPROTO_ICMP);
  if (socket_fd == -1) {
    // A permission denied error occurs when the sysctl parameter
    // net.ipv4.ping_group_range does not allow for the current
    // group to create a socket with IPPROTO_ICMP.

    perror("socket creation failure");
  }

  close(socket_fd);
  freeaddrinfo(address);
  address = NULL;

  return EXIT_SUCCESS;
} /* main() */
