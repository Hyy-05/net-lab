#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    buf_t buf;
    buf_init(&buf, sizeof(arp_pkt_t));
    
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf.data;
    *arp_pkt = arp_init_pkt;  // 拷贝初始化模板
    arp_pkt->opcode16 = swap16(ARP_REQUEST); // 设置操作码为请求
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN); // 填写目标IP
    
    // ARP 请求是以太网广播帧
    ethernet_out(&buf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    buf_t buf;
    buf_init(&buf, sizeof(arp_pkt_t));
    
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf.data;
    *arp_pkt = arp_init_pkt;  // 拷贝初始化模板
    arp_pkt->opcode16 = swap16(ARP_REPLY); // 设置操作码为响应
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN); // 填写目标IP
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN); // 填写目标MAC
    
    // ARP 响应是以太网单播帧
    ethernet_out(&buf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
     // 1. 长度检查，如果小于 ARP 包结构体大小，丢弃
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }
    
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    
    // 2. 更新 ARP 表
    // 只要收到了 ARP 包，就可以学习到对方的 IP 和 MAC 映射关系
    if (memcmp(arp_pkt->sender_ip, net_if_ip, NET_IP_LEN) != 0) {
        map_set(&arp_table, arp_pkt->sender_ip, src_mac);
    }
    
    // 3. 处理请求或响应
    uint16_t opcode = swap16(arp_pkt->opcode16);
    
    if (opcode == ARP_REQUEST) {
        // 如果目标 IP 是本机 IP，说明别人在找我，需要发送响应
        if (memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            arp_resp(arp_pkt->sender_ip, src_mac);
        }
    } else if (opcode == ARP_REPLY) {
        // 如果收到响应，检查我们之前是否有挂起（缓存）的要发给该 IP 的数据包
        if (memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            buf_t *pending_buf = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip);
            if (pending_buf != NULL) {
                // 发现有缓存的包，立即发送出去
                ethernet_out(pending_buf, src_mac, NET_PROTOCOL_IP);
                // 发送完毕后从缓存中删除，释放内存
                map_delete(&arp_buf, arp_pkt->sender_ip);
            }
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    // 1. 在 ARP 表中查找目标 IP 对应的 MAC 地址
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);
    
    if (mac != NULL) {
        // 找到了 MAC，直接通过以太网层发送 IP 数据包
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        // 2. 没找到 MAC，需要先缓存该数据包，并发起 ARP 请求
        // 使用 map_set 将数据包存入 arp_buf（底层会自动调用 buf_copy 深拷贝）
        // ret == 0 表示入队成功（未超频限制），可以发送 ARP 请求
        int ret = map_set(&arp_buf, ip, buf);
        if (ret == 0) {
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}