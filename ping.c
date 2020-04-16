/*
 *  ping.c
 *  Kevin Wu, April 13 2020
 *
 *  A toy implementation of the ping command in C.
 *
 *  References used:
 *    - https://stackoverflow.com/questions/8290046/icmp-sockets-linux
 *    - https://www.geeksforgeeks.org/ping-in-c/
 *    - https://beej.us/guide/bgnet/html
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>

#define RECV_DATA_MAX_SIZE (2048)

/*
 *  get_in_addr returns a pointer to the sockaddr_in
 *  or the sockaddr_in6 depending on the sa_family
 *  value (AF_INET, AF_INET6) of the input sockaddr.
 *
 *  Source: Beej's Guide to Network Programming.
 */

void* get_in_addr(struct sockaddr* sockaddr) {
  if (sockaddr->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sockaddr)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sockaddr)->sin6_addr);
} /* get_in_addr() */

/*
 *  get_dest_addresses uses getaddrinfo to resolve the
 *  given host name.
 *  It returns get a linked list of struct addrinfo
 *  that will be passed into socket() and sendto().
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
    perror("sendto() failure");
  }

  return bytes_sent;
} /* send_ping() */

/*
 *  recv_ping receives an ICMP packet from a given socket
 *  and prints out the packet's information.
 *
 *  The function returns the number of bytes received.
 */

int recv_ping(int socket_fd) {
  // Use recvmsg to find TTL
  // Source: https://stackoverflow.com/a/49308499

  uint8_t data[RECV_DATA_MAX_SIZE];
  struct iovec iov[1] = { { data, sizeof(data) } };
  struct sockaddr_storage src_addr;
  uint8_t ctrl_data_buffer[CMSG_SPACE(sizeof(uint8_t))];
  struct msghdr msg_header = {
    .msg_name = &src_addr,
    .msg_namelen = sizeof(src_addr),
    .msg_iov = iov,
    .msg_iovlen = 1,
    .msg_control = ctrl_data_buffer,
    .msg_controllen = sizeof(ctrl_data_buffer)
  };  // C99 designated initializers

  int bytes_read = recvmsg(socket_fd, &msg_header, 0);
  struct icmphdr* recv_icmp_header = (struct icmphdr*) data;

  if (bytes_read == -1) {
    perror("recvfrom() failure");
  }
  else if (bytes_read < sizeof(recv_icmp_header)) {
    fprintf(stderr, "Packet length shorter than expected"
                    "(expected %ld, got %d)\n",
                    sizeof(recv_icmp_header), bytes_read);
  }
  else {
    if (recv_icmp_header->type != ICMP_ECHOREPLY) {
      fprintf(stderr, "Packet type different from expected"
                      "(expected %d, got %d)\n",
                      ICMP_ECHOREPLY, recv_icmp_header->type);
    }
    else {
      int ttl = -1;
      struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg_header);
      for (; cmsg != NULL; cmsg = CMSG_NXTHDR(&msg_header, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_ICMP && 
            cmsg->cmsg_type == IP_RECVTTL) {
          ttl = *(uint8_t*)CMSG_DATA(cmsg);
          break;
        }
      }

      if (ttl == -1) {
        fprintf(stderr, "TTL was not found in message control data.\n");
      }

      char src_addr_name[INET6_ADDRSTRLEN];

      //TODO: record time
      printf("%d bytes from %s:  icmp_seq=%d ttl=%d\n",
             bytes_read,
             inet_ntop(src_addr.ss_family,
                       get_in_addr((struct sockaddr*)&src_addr),
                       src_addr_name, sizeof(src_addr_name)),
             recv_icmp_header->un.echo.sequence,
             ttl);
    }
  }
  return bytes_read;
} /* recv_ping() */

/*
 *  Main function for the ping program.
 */

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("No destination specified.\n");
    return EXIT_FAILURE;
  }

  //TODO: catch ctrl+C, print stats

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
    return EXIT_FAILURE;
  }

  // Set IP_RECVTTL sockopt to be able to parse TTL information
  int yes = 1;
  setsockopt(socket_fd, IPPROTO_ICMP, IP_RECVTTL, &yes, sizeof(yes));

  int num_sent = 0;
  while (true) {
    if (send_ping(socket_fd, address, num_sent++) == -1) {
      return EXIT_FAILURE;
    }

    if (recv_ping(socket_fd) == -1) {
      return EXIT_FAILURE;
    }

    sleep(1);
  }

  close(socket_fd);
  freeaddrinfo(address);
  address = NULL;

  return EXIT_SUCCESS;
} /* main() */
