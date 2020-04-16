/*
 *  ping.c
 *  Kevin Wu, April 13 2020
 *
 *  A toy implementation of the ping command in C.
 *
 *  References used:
 *    - https://stackoverflow.com/questions/8290046/icmp-sockets-linux
 *    - https://www.geeksforgeeks.org/ping-in-c/
 *    - https://www.cs.utah.edu/~swalton/listings/sockets/programs/part4/
        chap18/ping.c
 *    - https://beej.us/guide/bgnet/html
 */

#include <assert.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>

// Source: https://stackoverflow.com/a/12762101
#define MAX_ECHO_SEQUENCE (((unsigned long long)1 << \
        (sizeof(((struct icmphdr*)0)->un.echo.sequence) * CHAR_BIT)) - 1)
#define RECV_DATA_MAX_SIZE (2048)
#define PING_DATA_SIZE (56)

static volatile sig_atomic_t g_interrupt = 0;
static unsigned int g_packets_sent = 0;
static unsigned int g_packets_received = 0;
static long g_min_rtt = LONG_MAX;
static long g_max_rtt = 0;
static unsigned long long g_rtt_sum = 0;
uint8_t g_received_packet[(MAX_ECHO_SEQUENCE / CHAR_BIT) + 1] = { 0 };

struct icmp_packet_t {
  struct icmphdr icmp_header;
  long sent_micros;
  uint8_t padding[PING_DATA_SIZE - sizeof(long)];
};

/*
 *  timesepc_to_micros converts a struct timespec
 *  (seconds, nanoseconds) representation of time
 *  to a single long representing the number of
 *  microseconds since time 0.
 */

long timespec_to_micros(struct timespec ts) {
  return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
} /* timespec_to_micros() */

/*
 *  sigint_handler sets the g_interrupt variable
 *  when the program is interrupted.
 */

void sigint_handler(int sig) {
  g_interrupt = 1;
} /* sigint_handler() */

/*
 *  set_packet_state sets the bit in the g_received_packet
 *  bitmap according to the given state.
 */

void set_packet_state(int seq, bool state) {
  assert(seq < MAX_ECHO_SEQUENCE);
  int idx = seq / CHAR_BIT;
  int bit = seq % CHAR_BIT;

  if (state) {
    g_received_packet[idx] |= (1 << bit);
  }
  else {
    g_received_packet[idx] &= ~(1 << bit);
  }
} /* set_packet_state() */

/*
 *  is_packet_received returns whether or not the packet
 *  was previously received.
 */

bool is_packet_received(int seq) {
  assert(seq < MAX_ECHO_SEQUENCE);
  int idx = seq / CHAR_BIT;
  int bit = seq % CHAR_BIT;

  return (g_received_packet[idx] & (1 << bit)) != 0;
} /* is_packet_received() */

/*
 *  check_in_cksum checks the Internet checksum of
 *  a given number of bytes of data specified
 *  by RFC1071.
 */

bool check_in_cksum(void* buffer, int num_bytes) {
  uint16_t* data = (uint16_t*)buffer;
  uint32_t sum = 0;

  while (num_bytes > 1) {
    sum += *data;
    sum += (sum & (1 << 16)) ? 1 : 0;
    sum = (uint16_t)sum;
    data++;
    num_bytes -= sizeof(unsigned short);
  }

  if (num_bytes) {
    sum += *(unsigned char*)data;
    sum += (sum & (1 << 16)) ? 1 : 0;
    sum = (uint16_t)sum;
  }

  return (unsigned short)(sum + 1) == 0;
} /* check_in_cksum() */

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
  return address;
} /* get_dest_addresses() */

/*
 *  send_ping sends an ICMP packet to the given socket
 *  and destination address with the given sequence value.
 *
 *  The function returns the return value of sendto.
 */

int send_ping(int socket_fd, struct addrinfo* dest_addr) {
  struct icmp_packet_t icmp_packet = { 0 };

  icmp_packet.icmp_header.type = ICMP_ECHO;
  icmp_packet.icmp_header.un.echo.sequence = g_packets_sent++;
  // icmp_header.un.echo.id, checksum, etc. will be automatically set.
  // https://lwn.net/Articles/420800/

  struct timespec sent_time = { 0 };
  if (clock_gettime(CLOCK_MONOTONIC, &sent_time) == -1) {
    perror("clock_gettime() failure");
  }
  icmp_packet.sent_micros = timespec_to_micros(sent_time);

  set_packet_state(icmp_packet.icmp_header.un.echo.sequence, false);

  int bytes_sent = sendto(socket_fd, &icmp_packet, sizeof(icmp_packet), 0,
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
  struct sockaddr_storage src_addr = { 0 };
  uint8_t ctrl_data_buffer[CMSG_SPACE(sizeof(uint8_t))];
  struct msghdr msg_header = {
    .msg_name = &src_addr,
    .msg_namelen = sizeof(src_addr),
    .msg_iov = iov,
    .msg_iovlen = 1,
    .msg_control = ctrl_data_buffer,
    .msg_controllen = sizeof(ctrl_data_buffer)
  };  // C99 designated initializers

  struct timespec recv_time = { 0 };
  int bytes_read = recvmsg(socket_fd, &msg_header, 0);
  if (clock_gettime(CLOCK_MONOTONIC, &recv_time) == -1) {
    perror("clock_gettime() failure");
  }

  struct icmp_packet_t* recv_packet = (struct icmp_packet_t*) data;

  if (bytes_read == -1) {
    perror("recvfrom() failure");
  }
  else if (bytes_read != sizeof(struct icmp_packet_t)) {
    fprintf(stderr, "Packet length different than expected"
                    " (expected %ld, got %d)\n",
                    sizeof(struct icmp_packet_t), bytes_read);
  }
  else {
    if (recv_packet->icmp_header.type != ICMP_ECHOREPLY) {
      fprintf(stderr, "Packet type different than expected"
                      " (expected %d, got %d)\n",
                      ICMP_ECHOREPLY, recv_packet->icmp_header.type);
    }
    else {
      bool is_duplicate = false;
      if (is_packet_received(recv_packet->icmp_header.un.echo.sequence)) {
        is_duplicate = true;
      }
      else {
        set_packet_state(recv_packet->icmp_header.un.echo.sequence, false);
        g_packets_received++;
      }

      int ttl = -1;
      struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg_header);
      for (; cmsg; cmsg = CMSG_NXTHDR(&msg_header, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == IP_TTL)) {
          ttl = *(uint8_t*)CMSG_DATA(cmsg);
          break;
        }
      }

      if (ttl == -1) {
        fprintf(stderr, "TTL was not found in message control data.\n");
      }

      long recv_micros = timespec_to_micros(recv_time);
      long rtt = recv_micros - recv_packet->sent_micros;
      assert(rtt >= 0);

      if (!is_duplicate) {
        // duplicate packets should not affect min/max/avg rtt
        g_min_rtt = rtt < g_min_rtt ? rtt : g_min_rtt;
        g_max_rtt = rtt > g_max_rtt ? rtt : g_max_rtt;
        g_rtt_sum += rtt;
      }

      char src_addr_name[INET6_ADDRSTRLEN];
      printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%ld.%ld ms",
             bytes_read,
             inet_ntop(src_addr.ss_family,
                       get_in_addr((struct sockaddr*)&src_addr),
                       src_addr_name, sizeof(src_addr_name)),
             recv_packet->icmp_header.un.echo.sequence,
             ttl,
             rtt / 1000, rtt % 1000);

      if (!check_in_cksum(data, bytes_read)) {
        printf(" - checksum error");
      }
      if (is_duplicate) {
        printf(" - duplicate packet");
      }

      printf("\n");
    }
  }
  return bytes_read;
} /* recv_ping() */

/*
 *  Main function for the ping program.
 */

int main(int argc, char** argv) {
  signal(SIGINT, sigint_handler);

  if (argc < 2) {
    printf("No destination specified.\n");
    return EXIT_FAILURE;
  }

  char* destination = argv[1];

  struct addrinfo* address = get_dest_addresses(destination);
  if (!address) {
    return EXIT_FAILURE;
  }

  // Walk addrinfo linked list until one connects
  // TODO: IPv4/IPv6 selector
  char ip_addr_str[INET6_ADDRSTRLEN];
  int socket_fd = -1;
  for (struct addrinfo* addr_ptr = address; addr_ptr != NULL;
       addr_ptr = addr_ptr->ai_next) {
    socket_fd = socket(addr_ptr->ai_family, SOCK_DGRAM, IPPROTO_ICMP);
    if (socket_fd == -1) {
      continue;
    }

    void* sin_addr = NULL;

    if (addr_ptr->ai_family == AF_INET) {
      struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr_ptr->ai_addr;
      sin_addr = &ipv4->sin_addr;
    }
    else {
      struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr_ptr->ai_addr;
      sin_addr = &ipv6->sin6_addr;
    }

    inet_ntop(addr_ptr->ai_family, sin_addr, ip_addr_str, sizeof(ip_addr_str));

    printf("PING %s (%s): %d data bytes\n", destination, ip_addr_str,
           PING_DATA_SIZE);
    break;
  }

  if (socket_fd == -1) {
    // A permission denied error occurs when the sysctl parameter
    // net.ipv4.ping_group_range does not allow for the current
    // group to create a socket with IPPROTO_ICMP.
    perror("socket() failure");
    return EXIT_FAILURE;
  }


  // Set IP_RECVTTL sockopt to be able to parse TTL information
  int yes = 1;
  setsockopt(socket_fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes));

  while (!g_interrupt) {
    if (send_ping(socket_fd, address) == -1) {
      return EXIT_FAILURE;
    }

    if (recv_ping(socket_fd) == -1) {
      return EXIT_FAILURE;
    }

    sleep(1);
  }

  printf("\n--- %s ping statistics ---\n", destination);
  printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
         g_packets_sent, g_packets_received,
         ((float)(g_packets_sent - g_packets_received)) / g_packets_sent);

  if (g_packets_received > 0) {
    unsigned long long g_avg_rtt = g_rtt_sum / g_packets_received;
    printf("round-trip min/avg/max = %ld.%ld/%lld.%lld/%ld.%ld ms\n",
           g_min_rtt / 1000, g_min_rtt % 1000,
           g_avg_rtt / 1000, g_avg_rtt % 1000,
           g_max_rtt / 1000, g_max_rtt % 1000);
  }

  close(socket_fd);
  freeaddrinfo(address);
  address = NULL;

  return EXIT_SUCCESS;
} /* main() */
