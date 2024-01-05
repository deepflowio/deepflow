/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// the header file is locate in src/plugin/shared_obj/so_plugin.h
#include "so_plugin.h"

void init() { printf("on init\n"); }

#define DNS_RESPONSE 0x8000

#define DNS_QUERY_TYPE_A 0x0001
#define DNS_QUERY_TYPE_AAAA 28

#define CODE_MASK ntohs(15)

#define DNS_PROTO 1
#define DNS_PROTO_STR "custom_dns"

typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} dns_header;

typedef struct {
    unsigned char name[128];
    unsigned short type;
    unsigned short class;
} dns_question;

typedef struct {
    unsigned short type;
    unsigned char rdata[16];
} dns_resource_record;

// return offset in buf, -1 is fail
int parse_dns_request(unsigned char *buf, int buflen, dns_header *hdr,
                      dns_question *quest) {
    if (buflen < sizeof(dns_header) + 3) {
        return -1;
    }
    *hdr = *(dns_header *)buf;
    int off = 0;
    off += sizeof(dns_header);

    printf("DNS request:\n");
    printf("ID: %hu\n", ntohs(hdr->id));
    printf("Flags: %hu\n", ntohs(hdr->flags));
    printf("QDCOUNT: %hu\n", ntohs(hdr->qdcount));
    printf("ANCOUNT: %hu\n", ntohs(hdr->ancount));
    printf("NSCOUNT: %hu\n", ntohs(hdr->nscount));
    printf("ARCOUNT: %hu\n", ntohs(hdr->arcount));
    printf("---------------\n");
    for (int i = 0; i < ntohs(hdr->qdcount) && off < buflen; i++) {
        dns_question question;
        memset(&question.name[0], 0, sizeof(question.name));

        int name_off = 0;
        while (1) {
            if (off > buflen) {
                return -1;
            }
            unsigned int len = (unsigned int)(buf[off]);
            off += 1;
            if (len == 0) {
                break;
            }
            if (len + off > buflen) {
                return -1;
            }

            if (len + name_off +1 >= sizeof(question.name)) {
                memcpy(&question.name[name_off], &buf[off],
                       sizeof(question.name) - name_off - 1);
                off += len;
                break;
            } else {
                memcpy(&question.name[name_off], &buf[off], len);
                name_off += len;
                question.name[name_off] = '.';
                name_off += 1;
                off += len;
            }
        }

        if (off + 4 > buflen) {
            return -1;
        }

        question.type = ntohs(*(unsigned short *)(&buf[off]));
        off += 2;
        question.class = ntohs(*(unsigned short *)(&buf[off]));
        off += 2;
        printf("Question %d:\n", i + 1);
        printf("Name: %s\n", question.name);
        printf("Type: %hu\n", question.type);
        printf("Class: %hu\n", question.class);
        printf("---------------\n");

        if (question.type == DNS_QUERY_TYPE_A ||
            question.type == DNS_QUERY_TYPE_AAAA) {
            *quest = question;
        }
    }
    return off;
}

// -1 is fail, set the A or AAAA record to record ptr. only support compress ptr
int parse_dns_response(unsigned char *buf, int buflen, int req_off,
                       dns_header *hdr, dns_resource_record *record) {
    int off = req_off;
    for (int i = 0; i < ntohs(hdr->ancount) && off < buflen; i++) {
        if (off + 12 > buflen) {
            return -1;
        }
        unsigned short name = *(unsigned short *)(&buf[off]);
        unsigned short type = ntohs(*(unsigned short *)(&buf[off + 2]));
        unsigned short class = ntohs(*(unsigned short *)(&buf[off + 4]));
        unsigned int ttl = ntohl(*(unsigned int *)(&buf[off + 6]));
        unsigned int len =
            (unsigned int)ntohs(*(unsigned short *)(&buf[off + 10]));

        off += 12;
        if (off + len > buflen) {
            return -1;
        }
        printf("type: %d\n", type);
        printf("class: %d\n", class);
        printf("ttl: %d\n", ttl);
        printf("len: %d\n", len);
        if (type == DNS_QUERY_TYPE_A || type == DNS_QUERY_TYPE_AAAA) {
            if ((name & 0xc0) != 0xc0) {
                // only support name compress
                return -1;
            }
            int af;
            int addr_len;
            switch (len) {
                case 4:
                    af = AF_INET;
                    addr_len = INET_ADDRSTRLEN;
                    break;
                case 16:
                    af = AF_INET6;
                    addr_len = INET6_ADDRSTRLEN;
                    break;
                default:
                    return -1;
            }

            record->type = type;
            memcpy(&record->rdata[0], &buf[off], len);
            char ip_str[64];
            inet_ntop(af, &buf[off], &ip_str[0], addr_len);
            printf("ip: %s\n", ip_str);
        }

        printf("---------------\n");
        off += len;
    }
    return 0;
}

// int main() {
//     unsigned char resp[] = {
//         58,  166, 129, 128, 0, 1,  0,   2,   0,   0, 0,   1,  5,   98,
//         97,  105, 100, 117, 3, 99, 111, 109, 0,   0, 1,   0,  1,   192,
//         12,  0,   1,   0,   1, 0,  0,   0,   128, 0, 4,   39, 156, 66,
//         10,  192, 12,  0,   1, 0,  1,   0,   0,   0, 128, 0,  4,   110,
//         242, 68,  66,  0,   0, 41, 2,   0,   0,   0, 0,   0,  0,   0};
//     int buflen = sizeof(resp);

//     dns_header hdr;
//     dns_question quest;
//     int off = parse_dns_request(resp, buflen, &hdr, &quest);

//     dns_resource_record record;
//     parse_dns_response(resp, buflen, off, &hdr, &record);
// }

struct check_result on_check_payload(struct parse_ctx *ctx) {
    printf("===============on_check===========================\n");
    printf("ip type: %d\n", ctx->ip_type);
    printf("src: %d.%d.%d.%d:%d\n", ctx->ip_src[0], ctx->ip_src[1],
           ctx->ip_src[2], ctx->ip_src[3], ctx->port_src);
    printf("dst: %d.%d.%d.%d:%d\n", ctx->ip_dst[0], ctx->ip_dst[1],
           ctx->ip_dst[2], ctx->ip_dst[3], ctx->port_dst);
    printf("l4 proto: %d\n", ctx->l4_protocol);
    printf("proto: %d\n", ctx->proto);
    printf("ebpf type: %d\n", ctx->ebpf_type);
    printf("time: %d\n", ctx->time);
    printf("direction: %d\n", ctx->direction);
    printf("proc: %s\n", ctx->process_kname);
    printf("buf size: %d\n", ctx->buf_size);
    printf("payload size: %d\n", ctx->payload_size);
    for (int i = 0; i < ctx->payload_size; i++) {
        if (i > 0) printf(", ");
        printf("%d", ctx->payload[i]);
    }
    printf("\n");

    dns_header hdr;
    dns_question quest;
    struct check_result ret = {
        .proto = 0,
    };
    int off = parse_dns_request(ctx->payload, ctx->payload_size, &hdr, &quest);
    if (off == -1) {
        return ret;
    }
    if ((hdr.flags & DNS_RESPONSE) != 0) {
        return ret;
    }
    ret.proto = DNS_PROTO;
    memcpy(&ret.proto_name[0], DNS_PROTO_STR, sizeof(DNS_PROTO_STR));
    return ret;
}

struct parse_result on_parse_payload(struct parse_ctx *ctx,
                                     struct parse_info *infos, int infos_len) {
    if (ctx->proto != DNS_PROTO) {
        struct parse_result ret = {
            .action = ACTION_CONTINUE,
        };
        return ret;
    }
    printf("===============on_parse===========================\n");
    printf("ip type: %d\n", ctx->ip_type);
    printf("src: %d.%d.%d.%d:%d\n", ctx->ip_src[0], ctx->ip_src[1],
           ctx->ip_src[2], ctx->ip_src[3], ctx->port_src);
    printf("dst: %d.%d.%d.%d:%d\n", ctx->ip_dst[0], ctx->ip_dst[1],
           ctx->ip_dst[2], ctx->ip_dst[3], ctx->port_dst);
    printf("l4 proto: %d\n", ctx->l4_protocol);
    printf("proto: %d\n", ctx->proto);
    printf("ebpf type: %d\n", ctx->ebpf_type);
    printf("time: %d\n", ctx->time);
    printf("direction: %d\n", ctx->direction);
    printf("proc: %s\n", ctx->process_kname);
    printf("buf size: %d\n", ctx->buf_size);
    printf("payload size: %d\n", ctx->payload_size);
    for (int i = 0; i < ctx->payload_size; i++) {
        if (i > 0) printf(", ");
        printf("%d", ctx->payload[i]);
    }
    printf("\n");

    dns_header hdr;
    dns_question quest;
    struct parse_result ret = {
        .action = ACTION_ERROR,
        .len = 1,
    };
    int off = parse_dns_request(ctx->payload, ctx->payload_size, &hdr, &quest);

    if (off == -1) {
        return ret;
    }

    infos->request_id = ntohs(hdr.id);
    infos->has_request_id = 1;

    char trace_id[] = "this is trace id";
    char span_id[] = "this is span id";
    char parent_span_id[] = "this is parent span id";
    memcpy(&infos->trace.trace_id[0], trace_id, sizeof(trace_id));
    memcpy(&infos->trace.span_id[0], span_id, sizeof(span_id));
    memcpy(&infos->trace.parent_span_id[0], parent_span_id,
           sizeof(parent_span_id));

    char key1[] = "key1";
    char key2[] = "key2";
    char val1[] = "val1";
    char val2[] = "val2";

    memcpy(&infos->attributes[0], key1, sizeof(key1));
    memcpy(&infos->attributes[sizeof(key1)], val1, sizeof(val1));
    memcpy(&infos->attributes[sizeof(key1) + sizeof(val1)], key2, sizeof(key2));
    memcpy(&infos->attributes[sizeof(key1) + sizeof(val1) + sizeof(key2)], val2,
           sizeof(val2));
    infos->attr_len = 2;

    if ((hdr.flags & DNS_RESPONSE) == 0) {
        infos->msg_type = MSG_TYPE_REQ;
        switch (quest.type) {
            case DNS_QUERY_TYPE_A:
                infos->req_resp.req.req_type[0] = 'A';
                break;
            case DNS_QUERY_TYPE_AAAA:
                memcpy(&infos->req_resp.req.req_type[0], "AAAA", 4);
                break;
        }
        strcpy(&infos->req_resp.req.domain[0], &quest.name[0]);
        ret.action = ACTION_OK;
        return ret;
    }

    infos->msg_type = MSG_TYPE_RESP;
    infos->req_resp.resp.code = hdr.flags & CODE_MASK;
    if (infos->req_resp.resp.code != 0) {
        infos->req_resp.resp.status = RESP_STATUS_CLIENT_ERR;
        ret.action = ACTION_OK;
        return ret;
    }

    dns_resource_record record;
    if (parse_dns_response(ctx->payload, ctx->payload_size, off, &hdr,
                           &record) == -1) {
        return ret;
    }

    infos->req_resp.resp.status = RESP_STATUS_OK;
    switch (record.type) {
        case DNS_QUERY_TYPE_A:
            inet_ntop(AF_INET, &record.rdata[0],
                      &infos->req_resp.resp.result[0], INET_ADDRSTRLEN);
            break;
        case DNS_QUERY_TYPE_AAAA:
            inet_ntop(AF_INET6, &record.rdata[0],
                      &infos->req_resp.resp.result[0], INET6_ADDRSTRLEN);
            break;
    }
    ret.action = ACTION_OK;
    return ret;
}
