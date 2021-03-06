#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef struct {
  uint16_t class;
  uint16_t type;
  uint8_t* name;

  uint32_t ttl;
  uint8_t* value;
} record_t;

int fd = 0;
record_t* records = NULL;
uint32_t nrecords = 0;

uint8_t msg[8192];
uint32_t n;

uint8_t reply[8192];
uint32_t m;

#define DNS_NOERROR  0
#define DNS_FORMERR  1
#define DNS_NXDOMAIN 3
#define DNS_NOTIMP   4

void die() {
  perror("dns");
  exit(-1);
}

void buf_putnum(uint32_t n, uint8_t bytes) {
  while (bytes--) {
    reply[m++] = (n>>(bytes*8))&0xFF;
  }
}

void buf_putbuf(const uint8_t* b, uint8_t n) {
  memcpy(reply+m, b, n);
  m += n;
}

void dns_build_header(int response, int ancount) {
  memset(reply, 0, 12);
  memcpy(reply, msg, 2);
  memcpy(reply+4, msg+4, 2);

  reply[2] = (msg[2] & 0x78) | 0x84; // 01111000 | 10000100
  reply[3] = (msg[3] & 0x00) | response; // 00000000 | 00000000

  reply[6] = (ancount>>8)&0xFF;
  reply[7] = ancount&0xFF;
}

void buf_putname(const uint8_t* name) {
  const uint8_t* p = name;

  while (*p) {
    uint32_t offset = 0;
    while (p[offset++] != '.');

    buf_putnum(offset-1, 1);
    buf_putbuf(p, offset-1);
    p += offset;
  }
  buf_putnum(0, 1);
}

void dns_add_response(const record_t* rr) {
  uint16_t rdlength = strlen((const char*)rr->value);

  buf_putname(rr->name);
  buf_putnum(rr->type, 2);
  buf_putnum(rr->class, 2);
  buf_putnum(rr->ttl, 4);
  buf_putnum(rdlength, 2);
  buf_putbuf(rr->value, rdlength);
}

int dns_resolve(const uint8_t* name, uint16_t type, uint16_t class) {
  uint32_t i = 0;
  uint32_t answers = 0;

  for (i = 0; i < nrecords; ++i) {
    if (records[i].class == class &&
        records[i].type == type &&
        !strcmp((char*)records[i].name, (char*)name)) {
          dns_add_response(&records[i]);
          ++answers;
    }
  }

  return answers;
}

int dns_is_query() {
  return (msg[2] & 0x80) == 0;
}

uint16_t dns_query_count() {
  return msg[4] << 8 | msg[5];
}

int dns_read_name(uint8_t* name, int* offset) {
  while (*offset < n) {
    uint8_t length = msg[(*offset)++];

    if (length == 0) {
      *name = 0;
      return 0;
    }

    if ((length & 0xA0) == 0xA0) {
      int new_offset = length & 0x3F;
      return dns_read_name(name, &new_offset);
    }

    if (length + *offset > n) {
      return 1;
    }

    memcpy(name, msg + *offset, length);
    name += length;
    *name++ = '.';

    *offset += length;
  }
  return 1;
}

int dns_extract_query(uint8_t* name, uint16_t* type, uint16_t* class) {
  int offset = 12;

  if (n < 12) {
    return DNS_FORMERR;
  }

  if (!dns_is_query()) {
    return DNS_FORMERR;
  }

  if (dns_query_count() != 1) {
    return DNS_NOTIMP;
  }

  if (dns_read_name(name, &offset) != 0) {
    return DNS_FORMERR;
  }

  *type = msg[offset+0] << 8 | msg[offset+1];
  *class = msg[offset+2] << 8 | msg[offset+3];
  return DNS_NOERROR;
}


void dns_process() {
  uint8_t name[512];
  uint16_t type;
  uint16_t class;

  m = 12;

  int code = dns_extract_query(name, &type, &class);
  if (code != DNS_NOERROR) {
    dns_build_header(code, 0);
    return;
  }

  buf_putname(name);
  buf_putnum(type, 2);
  buf_putnum(class, 2);

  int an = dns_resolve(name, type, class);

  if (an == 0) {
    dns_build_header(DNS_NXDOMAIN, 0);
  } else {
    dns_build_header(DNS_NOERROR, an);
  }
}

void createsocket(uint16_t port) {
  struct sockaddr_in6 addr;
  int optval = 1;

  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_any;
  addr.sin6_port = htons(port);

  fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    die();
  }

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    die();
  }
}

void readrecords(const char* fname) {
  char name[512];
  char value[4096];
  uint32_t class, type;
  uint32_t ttl;

  FILE* fp = fopen(fname, "rb");
  if (!fp) {
    die();
  }

  free(records);
  nrecords = 0;
  records = NULL;
  while (fscanf(fp, "%s %u %u %u %[^\n]\n", name, &class, &type, &ttl, value) == 5) {
    records = realloc(records, (1+nrecords)*sizeof(record_t));

    records[nrecords].class = class;
    records[nrecords].type = type;
    records[nrecords].name = (uint8_t*)strdup(name);
    records[nrecords].ttl = ttl;

    if (class == 1 && type == 1) {
      struct in_addr inp;
      inet_aton(value, &inp);
      memcpy(value, &inp.s_addr, 4);
      value[4] = 0;
    }

    records[nrecords].value = (uint8_t*)strdup(value);
    nrecords++;
  }

  fclose(fp);
}

int main() {
  struct sockaddr_in6 addr;
  socklen_t addrlen = sizeof(addr);

  createsocket(5354);
  readrecords("records.txt");

  while ((n = recvfrom(fd, msg, sizeof(msg), 0, (struct sockaddr*)&addr, &addrlen)) > 0) {
    dns_process(msg, n);
    sendto(fd, reply, m, 0, (struct sockaddr*)&addr, addrlen);
  }

  return 0;
}
