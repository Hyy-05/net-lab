#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 1. 长度检查：至少包含一个完整的 IP 头部
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }

    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // 2. 检查版本号（IPv4 的版本号为 4）
    if (ip_hdr->version != 4) {
        return;
    }

    // 3. 获取头部长度（单位是 4 字节）
    int hdr_len = ip_hdr->hdr_len * 4;
    if (hdr_len < sizeof(ip_hdr_t) || buf->len < hdr_len) {
        return;
    }

    // 4. 校验 IP 数据包总长度
    uint16_t total_len = swap16(ip_hdr->total_len16);
    if (buf->len < total_len) {
        return; // 实际收到长度比声明的总长度还短，数据不完整
    }
    if (buf->len > total_len) {
        // 实际收到长度大于声明总长度，说明底层带上了 Padding，需要截断
        buf->len = total_len; 
    }

    // 5. IP 头部校验和检查
    uint16_t calc_chksum = checksum16((uint16_t *)ip_hdr, hdr_len);
    if (calc_chksum != 0) { 
        // 如果计算结果不为 0，说明校验失败，丢弃
        return;
    }

    // 6. 检查目标 IP 地址是否为本机 IP
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return; // 不是发给本机的包，丢弃
    }

    // 7. 提取源 IP 和上层协议号，准备向上层递交
    uint8_t src_ip[NET_IP_LEN];
    memcpy(src_ip, ip_hdr->src_ip, NET_IP_LEN);
    net_protocol_t protocol = ip_hdr->protocol;

    // 8. 移除 IP 头部，调用 net_in 传递数据给上层
    buf_remove_header(buf, hdr_len);
    if (net_in(buf, protocol, src_ip) < 0) {
    // 上层协议未注册处理器，恢复 IP 头并回送协议不可达
    buf_add_header(buf, hdr_len);
    icmp_unreachable(buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    // 1. 添加 IP 头部
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // 2. 填写各字段
    ip_hdr->version = 4;
    ip_hdr->hdr_len = 5; // 5 * 4 = 20 字节
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len); // 包含 IP 头和负载的总长度
    ip_hdr->id16 = swap16(id);
    
    // 标志位 MF 占 3 位中的最低位（在 16 位中占第 13 位），offset 为偏移量/8
    ip_hdr->flags_fragment16 = swap16((mf << 13) | (offset / 8));
    
    ip_hdr->ttl = 64; // 默认跳数
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0; // 计算前先置 0
    
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // 3. 计算头部校验和
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));

    // 4. 通过 ARP 层发送出去
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    static uint16_t ip_id = 0; 
    uint16_t current_id = ip_id++; 

    // 计算 MTU 允许的最大载荷（1500 - 20 = 1480，且必须是 8 的倍数）
    int max_payload = (ETHERNET_MAX_TRANSPORT_UNIT - 20) / 8 * 8;

    // 如果不需要分片，直接发送
    if (buf->len <= max_payload) {
        ip_fragment_out(buf, ip, protocol, current_id, 0, 0);
        return;
    }

    // 需要分片：使用原 buf 的数据进行拷贝
    int offset = 0;
    uint8_t *src_data = buf->data;
    int rem_len = buf->len;

    while (rem_len > 0) {
        // 当前分片的载荷长度
        int current_payload = rem_len > max_payload ? max_payload : rem_len;
        
        // 分配足够大的新缓冲区（载荷 + IP 头部空间，防止 buf_add_header 越界）
        buf_t frag;
        buf_init(&frag, current_payload + 20); 
        
        // 将数据拷贝到新缓冲区
        memcpy(frag.data, src_data, current_payload);
        frag.len = current_payload;
        
        // 判断是否还有后续分片 
        int mf = (rem_len > max_payload) ? 1 : 0;
        
        // 发送分片
        ip_fragment_out(&frag, ip, protocol, current_id, offset, mf);
        
        // 移动指针并更新剩余长度
        offset += current_payload;
        src_data += current_payload;
        rem_len -= current_payload;
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}