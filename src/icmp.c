#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    // Step1: 将报文类型改为回显响应
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)req_buf->data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;

    // Step2: 重新计算校验和
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)req_buf->data, req_buf->len);

    // Step3: 通过IP层发送回源IP
    ip_out(req_buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    // Step1: 数据长度不足以太网头部长度，丢弃
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;
    }

    // Step2: 获取ICMP头部
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;

    // Step3: 根据类型分发处理
    switch (icmp_hdr->type) {
        case ICMP_TYPE_ECHO_REQUEST:
            icmp_resp(buf, src_ip);
            break;

        default:
            break;
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    // Step1: 计算需要保留的长度（IP首部 + 前8字节负载）
    ip_hdr_t *ip_hdr = (ip_hdr_t *)recv_buf->data;
    size_t keep_len = ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE + 8;

    // Step2: 移除超出保留长度的尾部数据
    if (recv_buf->len > keep_len) {
        buf_remove_padding(recv_buf, recv_buf->len - keep_len);
    }

    // Step3: 添加ICMP头部
    buf_add_header(recv_buf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)recv_buf->data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)recv_buf->data, recv_buf->len);

    // Step4: 发送不可达报文给原IP
    ip_out(recv_buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}