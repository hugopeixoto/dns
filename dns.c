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

uint8_t msg[8192];
uint32_t n;

uint8_t reply[8192];
uint32_t m;

#define DNS_NOERROR  0
#define DNS_FORMERR  1
#define DNS_NXDOMAIN 3
#define DNS_NOTIMP   4

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

  reply[2] = (msg[2] & 0x78) | 0x84; // 01111000 | 10000100
  reply[3] = (msg[3] & 0x00) | response; // 00000000 | 00000000

  reply[6] = (ancount>>8)&0xFF;
  reply[7] = ancount&0xFF;
}

void dns_add_response(const record_t* rr) {
  uint16_t rdlength = strlen((const char*)rr->value);
  uint8_t* p = rr->name;

  while (*p) {
    uint32_t offset = 0;
    while (p[offset++] != '.');

    buf_putnum(offset-1, 1);
    buf_putbuf(p, offset-1);
    p += offset;
  }

  buf_putnum(0, 1);
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
          printf("Query[%u][%u][%s]: [%s]\n", class, type, name, records[i].value);
          dns_add_response(&records[i]);
          ++answers;
    }
  }

  if (answers == 0) {
    printf("Query[%u][%u][%s]: NOT FOUND\n", class, type, name);
  }

  return answers;
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

int dns_read_name(const uint8_t* msg, uint32_t n, uint8_t* name, int* offset) {
  while (*offset < n) {
    uint8_t length = msg[(*offset)++];

    if (length == 0) {
      *name = 0;
      return 0;
    }

    if ((length & 0xA0) == 0xA0) {
      int new_offset = length & 0x3F;
      return dns_read_name(msg, n, name, &new_offset);
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

  if (!dns_is_query(msg, n)) {
    return DNS_FORMERR;
  }

  if (dns_query_count(msg, n) != 1) {
    return DNS_NOTIMP;
  }

  if (dns_read_name(msg, n, name, &offset) != 0) {
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

  int an = dns_resolve(name, type, class);

  if (an == 0) {
    dns_build_header(DNS_NXDOMAIN, 0);
  } else {
    dns_build_header(DNS_NOERROR, an);
  }
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
  records[0].value = (uint8_t*)strdup("\xC3\xC8\xFD\x88");

  return 0;
}

void dns_log() {
  FILE* fp = fopen("log.txt", "a+");
  fwrite(reply, m, 1, fp);
  fclose(fp);
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
    dns_process(msg, n);
    dns_log();
    sendto(s, reply, m, 0, &src_addr, src_addrlen);
  }

  return 0;
}
