#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>

typedef struct {
  uint16_t class;
  uint16_t type;
  uint8_t* name;

  uint32_t ttl;
  uint8_t* value;
} record_t;

record_t* records;
uint32_t nrecords;

uint8_t msg[1024];
uint32_t n;

uint8_t reply[8192];
uint32_t m;

int dns_build_header() {
  memset(reply, 0, 12);
  memcpy(reply, msg, 4);

  reply[2] |= 0xA0;

  m = 12;
}

int dns_add_response(const record_t* rr) {
  printf(
    "Query: [%u][%u][%s] = [%s]\n",
    rr->class,
    rr->type,
    rr->name,
    rr->value);

  return 0;
}

int dns_resolve(uint16_t class, uint16_t type, const uint8_t* name) {
  uint32_t i = 0;

  for (i = 0; i < nrecords; ++i) {
    if (records[i].class == class &&
        records[i].type == type &&
        !strcmp((char*)records[i].name, (char*)name)) {
          dns_add_response(&records[i]);
      return 0;
    }
  }

  printf("Query: [%u][%u][%s] = NOT FOUND\n", class, type, name);
  return -1;
}


uint16_t dns_id(const uint8_t* msg, uint32_t n) {
  return msg[0] << 8 | msg[1];
}

int dns_is_query(const uint8_t* msg, uint32_t n) {
  return (msg[2] & 0x80) == 0;
}

uint16_t dns_query_count(const uint8_t* msg, uint32_t n) {
  return msg[4] << 8 | msg[5];
}

uint16_t dns_answer_count(const uint8_t* msg, uint32_t n) {
  return msg[6] << 8 | msg[7];
}

int dns_read_name(const uint8_t* msg, uint32_t n, uint8_t* name, int* offset) {
  while (*offset < n) {
    uint8_t label_size = msg[(*offset)++];

    if (label_size == 0) {
      *name = 0;
      return 0;
    }

    if (label_size + *offset > n) {
      return 1;
    }

    memcpy(name, msg + *offset, label_size);
    name += label_size;
    *name++ = '.';

    *offset += label_size;
  }

  return 1;
}

int dns_answer_queries(const uint8_t* msg, uint32_t n) {
  int offset = 12;
  uint8_t name[512];

  uint16_t qc = dns_query_count(msg, n);

  while (qc--) {
    int err = dns_read_name(msg, n, name, &offset);
    if (err != 0 || offset + 4 > n) {
      return -1;
    }

    dns_resolve(msg[offset+2] << 8 | msg[offset+3],
        msg[offset] << 8 | msg[offset+1],
        name);
  }

  return 0;
}

int process() {
  m = 0;

  if (n < 12) {
    printf("Not enough bytes: %u < 12\n", n);
    return -1;
  }

  if (!dns_is_query(msg, n)) {
    printf("Received something that isn't a query\n");
    return -2;
  }

  printf("ID: %X\n", dns_id(msg, n));
  printf("QC: %u\n", dns_query_count(msg, n));

  dns_build_header();
  dns_answer_queries(msg, n);

  return 0;
}

int createsocket(uint16_t port) {
  struct sockaddr_in addr;
  int optval = 1;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    fprintf(stderr, "error socket(): %d", s);
    return -3;
  }

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(optval));

  int b = bind(s, (struct sockaddr*)&addr, sizeof(addr));
  if (b < 0) {
    fprintf(stderr, "error bind(): %d", errno);
    return -2;
  }

  return s;
}

int readrecords(const char* fname) {
  nrecords = 1;
  records = malloc(sizeof(record_t)*nrecords);

  records[0].class = 1;
  records[0].type = 1;
  records[0].name = (uint8_t*)strdup("hugopeixoto.net.");

  records[0].ttl = 3519;
  records[0].value = (uint8_t*)strdup("195.200.253.136");

  return 0;
}

int main() {
  int s = createsocket(5354);
  if (s < 0) {
    return -1;
  }

  if (readrecords("records.txt") < 0) {
    return -2;
  }

  struct sockaddr src_addr;
  socklen_t src_addrlen;

  while ((n = recvfrom(s, msg, sizeof(msg), 0, &src_addr, &src_addrlen)) > 0) {
    process(msg, n);

    if (m > 0) {
      sendto(s, reply, m, 0, &src_addr, src_addrlen);
    }
  }

  return 0;
}
