#include <stdarg.h>    // 修复 va_start, va_end 错误
#include <signal.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <getopt.h>
#include <openssl/md5.h>

// 配置参数
#define SERVER_IP ""
#define USERNAME "phonenumber"
#define PASSWORD "password"
#define CONTROLCHECKSTATUS 0x内容
#define ADAPTERNUM 0x内容
#define HOST_IP ""
#define IPDOG 0x内容
#define HOST_NAME "内容"
#define PRIMARY_DNS ""
#define DHCP_SERVER ""
#define MAC_ADDR {内容}
#define HOST_OS "Windows 10"
#define KEEP_ALIVE_VERSION "undefined"
#define AUTH_VERSION {0x内容, 0x内容}
#define SERVER_PORT 61440
#define CLIENT_PORT 61440

// 全局变量
bool is_running = true;
bool reconnect_flag = false;
bool debug_mode = false;
time_t last_keepalive_time = 0;
int keepalive_counter = 0;
unsigned char current_tail[4] = {0};
int sockfd = 0;

// 日志函数
void log_msg(const char* format, ...) {
    if (!debug_mode) return;
    
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("[%s] ", timestamp);
    vprintf(format, args);
    printf("\n");
    
    va_end(args);
}

// 创建UDP套接字
int create_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(CLIENT_PORT);
    
    if (bind(sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    return sock;
}

// 生成随机数
unsigned short random_ushort() {
    return (unsigned short)(rand() % 0xFFFF);
}

// MD5哈希计算
void md5sum(const unsigned char* data, size_t len, unsigned char* digest) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(digest, &ctx);
}

// 挑战函数
int challenge(const char* server_ip, unsigned char* salt) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    unsigned char packet[20];
    unsigned short t = random_ushort();
    
    packet[0] = 0x01;
    packet[1] = 0x02;
    memcpy(packet + 2, &t, sizeof(t));
    packet[4] = 0x09;
    memset(packet + 5, 0, 15);
    
    for (int attempt = 0; attempt < 5 && is_running; attempt++) {
        if (sendto(sockfd, packet, sizeof(packet), 0, 
                  (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            log_msg("[challenge] Send failed");
            continue;
        }
        
        unsigned char response[1024];
        socklen_t addr_len = sizeof(server_addr);
        ssize_t recv_len = recvfrom(sockfd, response, sizeof(response), 0, 
                                   (struct sockaddr*)&server_addr, &addr_len);
        
        if (recv_len > 0 && response[0] == 0x02) {
            memcpy(salt, response + 4, 4);
            log_msg("[challenge] Success, salt: %02x%02x%02x%02x", 
                   salt[0], salt[1], salt[2], salt[3]);
            return 1;
        }
        
        log_msg("[challenge] Timeout/error, retrying...");
        sleep(2);
    }
    
    log_msg("[challenge] Failed after 5 attempts");
    return 0;
}

// 构建心跳包
void build_keep_alive_packet(int number, int pkg_type, const unsigned char* tail, 
                             unsigned char* packet, size_t* packet_len) {
    packet[0] = 0x07;
    packet[1] = (unsigned char)number;
    packet[2] = 0x28;
    packet[3] = 0x00;
    packet[4] = 0x0b;
    packet[5] = (unsigned char)pkg_type;
    
    if (pkg_type == 1) {
        // 类型1心跳包
        memcpy(packet + 6, KEEP_ALIVE_VERSION, strlen(KEEP_ALIVE_VERSION));
        packet[6 + strlen(KEEP_ALIVE_VERSION)] = 0x2f;
        packet[7 + strlen(KEEP_ALIVE_VERSION)] = 0x12;
        memset(packet + 8 + strlen(KEEP_ALIVE_VERSION), 0, 6);
        
        size_t offset = 14 + strlen(KEEP_ALIVE_VERSION);
        memcpy(packet + offset, tail, 4);
        offset += 4;
        memset(packet + offset, 0, 4);
        offset += 4;
        
        // 添加主机IP
        memset(packet + offset, 0, 12);
        offset += 12;
        
        unsigned char ip_bytes[4];
        sscanf(HOST_IP, "%hhu.%hhu.%hhu.%hhu", 
               &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
        memcpy(packet + offset, ip_bytes, 4);
        offset += 4;
        
        *packet_len = offset;
    } else if (pkg_type == 3) {
        // 类型3心跳包
        packet[6] = 0x0f;
        packet[7] = 0x27;
        packet[8] = 0x2f;
        packet[9] = 0x12;
        memset(packet + 10, 0, 6);
        
        size_t offset = 16;
        memcpy(packet + offset, tail, 4);
        offset += 4;
        memset(packet + offset, 0, 4);
        offset += 4;
        
        // 添加IP地址和CRC
        unsigned char ip_bytes[4];
        sscanf(HOST_IP, "%hhu.%hhu.%hhu.%hhu", 
               &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
        
        unsigned char digest[MD5_DIGEST_LENGTH];
        md5sum(ip_bytes, 4, digest);
        memcpy(packet + offset, digest, 4);
        offset += 4;
        
        memcpy(packet + offset, ip_bytes, 4);
        offset += 4;
        memset(packet + offset, 0, 8);
        offset += 8;
        
        // 添加计数器
        memcpy(packet + offset, &keepalive_counter, sizeof(keepalive_counter));
        offset += 4;
        
        *packet_len = offset;
    }
}

// 自适应心跳机制
void* adaptive_keep_alive(void* arg) {
    const char* server_ip = (const char*)arg;
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    int seq_num = 1;
    int failures = 0;
    int base_interval = 25;
    int min_interval = 15;
    int max_interval = 45;
    int current_interval = base_interval;
    
    while (is_running && !reconnect_flag) {
        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, last_keepalive_time);
        
        if (elapsed < current_interval) {
            sleep(current_interval - (int)elapsed);
            continue;
        }
        
        last_keepalive_time = current_time;
        keepalive_counter++;
        
        // 发送类型1心跳包
        unsigned char packet1[128];
        size_t packet1_len;
        build_keep_alive_packet(seq_num, 1, current_tail, packet1, &packet1_len);
        
        if (sendto(sockfd, packet1, packet1_len, 0, 
                  (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            log_msg("[keep-alive] Send type1 failed");
        } else {
            log_msg("[keep-alive] Sent type1 packet #%d, interval: %ds", seq_num, current_interval);
        }
        
        // 设置接收超时
        struct timeval tv = {8, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        unsigned char response[1024];
        socklen_t addr_len = sizeof(server_addr);
        ssize_t recv_len = recvfrom(sockfd, response, sizeof(response), 0, 
                                   (struct sockaddr*)&server_addr, &addr_len);
        
        if (recv_len > 0 && response[0] == 0x07) {
            memcpy(current_tail, response + 16, 4);
            log_msg("[keep-alive] Received response, new tail: %02x%02x%02x%02x", 
                   current_tail[0], current_tail[1], current_tail[2], current_tail[3]);
            
            failures = 0;
            current_interval = (current_interval + 2 > max_interval) ? max_interval : current_interval + 2;
        } else {
            log_msg("[keep-alive] Type1 response timeout or error");
            failures++;
            current_interval = (current_interval - 5 < min_interval) ? min_interval : current_interval - 5;
        }
        
        // 每3次心跳发送类型3包
        if (keepalive_counter % 3 == 0) {
            seq_num = (seq_num + 1) % 256;
            unsigned char packet3[128];
            size_t packet3_len;
            build_keep_alive_packet(seq_num, 3, current_tail, packet3, &packet3_len);
            
            if (sendto(sockfd, packet3, packet3_len, 0, 
                      (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                log_msg("[keep-alive] Send type3 failed");
            } else {
                log_msg("[keep-alive] Sent type3 packet #%d", seq_num);
            }
            
            // 检查响应
            recv_len = recvfrom(sockfd, response, sizeof(response), 0, 
                               (struct sockaddr*)&server_addr, &addr_len);
            
            if (recv_len > 0 && response[0] == 0x07) {
                memcpy(current_tail, response + 16, 4);
                failures = 0;
            } else {
                log_msg("[keep-alive] Type3 response timeout");
            }
        }
        
        // 失败处理
        if (failures >= 2) {
            log_msg("[keep-alive] Too many failures, re-authenticating...");
            reconnect_flag = true;
            break;
        }
        
        seq_num = (seq_num + 1) % 256;
    }
    
    return NULL;
}

// 发送keep-alive1包
int send_keep_alive1(const unsigned char* salt, const unsigned char* tail, const char* password, const char* server_ip) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    unsigned char data[128];
    data[0] = 0xff;
    
    // 计算MD5
    unsigned char md5_input[100];
    md5_input[0] = 0x03;
    md5_input[1] = 0x01;
    memcpy(md5_input + 2, salt, 4);
    memcpy(md5_input + 6, password, strlen(password));
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    md5sum(md5_input, 6 + strlen(password), digest);
    memcpy(data + 1, digest, MD5_DIGEST_LENGTH);
    
    memset(data + 1 + MD5_DIGEST_LENGTH, 0, 3);
    memcpy(data + 1 + MD5_DIGEST_LENGTH + 3, tail, 4);
    
    unsigned short foo = (unsigned short)(time(NULL) % 0xFFFF);
    memcpy(data + 1 + MD5_DIGEST_LENGTH + 3 + 4, &foo, sizeof(foo));
    memset(data + 1 + MD5_DIGEST_LENGTH + 3 + 4 + 2, 0, 4);
    
    size_t data_len = 1 + MD5_DIGEST_LENGTH + 3 + 4 + 2 + 4;
    
    if (sendto(sockfd, data, data_len, 0, 
              (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_msg("[keep-alive1] Send failed");
        return 0;
    }
    
    log_msg("[keep-alive1] Sent");
    
    // 等待响应
    struct timeval tv = {3, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    unsigned char response[1024];
    socklen_t addr_len = sizeof(server_addr);
    if (recvfrom(sockfd, response, sizeof(response), 0, 
                (struct sockaddr*)&server_addr, &addr_len) > 0) {
        log_msg("[keep-alive1] Received response");
    } else {
        log_msg("[keep-alive1] Response timeout");
    }
    
    return 1;
}

// 登录认证
int login(const char* username, const char* password, const char* server_ip, unsigned char* tail) {
    unsigned char salt[4];
    if (!challenge(server_ip, salt)) {
        log_msg("[login] Failed to get challenge salt");
        return 0;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    // 构建登录包
    unsigned char packet[256];
    size_t offset = 0;
    
    packet[offset++] = 0x03;
    packet[offset++] = 0x01;
    packet[offset++] = 0x00;
    packet[offset++] = (unsigned char)(strlen(username) + 20);
    
    // 计算MD5
    unsigned char md5_input[100];
    md5_input[0] = 0x03;
    md5_input[1] = 0x01;
    memcpy(md5_input + 2, salt, 4);
    memcpy(md5_input + 6, password, strlen(password));
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    md5sum(md5_input, 6 + strlen(password), digest);
    memcpy(packet + offset, digest, MD5_DIGEST_LENGTH);
    offset += MD5_DIGEST_LENGTH;
    
    // 用户名
    memcpy(packet + offset, username, strlen(username));
    offset += strlen(username);
    memset(packet + offset, 0, 36 - strlen(username));
    offset += 36 - strlen(username);
    
    packet[offset++] = CONTROLCHECKSTATUS;
    packet[offset++] = ADAPTERNUM;
    
    // MAC地址处理
    unsigned char mac_addr[] = MAC_ADDR;
    for (int i = 0; i < 6; i++) {
        packet[offset++] = digest[i] ^ mac_addr[i];
    }
    
    // 密码MD5
    md5_input[0] = 0x01;
    memcpy(md5_input + 1, password, strlen(password));
    memcpy(md5_input + 1 + strlen(password), salt, 4);
    memset(md5_input + 1 + strlen(password) + 4, 0, 4);
    md5sum(md5_input, 1 + strlen(password) + 8, digest);
    memcpy(packet + offset, digest, MD5_DIGEST_LENGTH);
    offset += MD5_DIGEST_LENGTH;
    
    // 主机IP
    packet[offset++] = 0x01;
    unsigned char ip_bytes[4];
    sscanf(HOST_IP, "%hhu.%hhu.%hhu.%hhu", 
           &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
    memcpy(packet + offset, ip_bytes, 4);
    offset += 4;
    
    memset(packet + offset, 0, 12);
    offset += 12;
    
    // 校验和
    unsigned char crc_data[256];
    memcpy(crc_data, packet, offset);
    crc_data[offset] = 0x14;
    crc_data[offset + 1] = 0x00;
    crc_data[offset + 2] = 0x07;
    crc_data[offset + 3] = 0x0b;
    memcpy(crc_data + offset + 4, mac_addr, 6);
    
    md5sum(crc_data, offset + 10, digest);
    memcpy(packet + offset, digest, 8);
    offset += 8;
    
    // 其他字段
    packet[offset++] = IPDOG;
    memset(packet + offset, 0, 4);
    offset += 4;
    
    // 主机名
    memcpy(packet + offset, HOST_NAME, strlen(HOST_NAME));
    offset += strlen(HOST_NAME);
    memset(packet + offset, 0, 32 - strlen(HOST_NAME));
    offset += 32 - strlen(HOST_NAME);
    
    // DNS服务器
    unsigned char dns_bytes[4];
    sscanf(PRIMARY_DNS, "%hhu.%hhu.%hhu.%hhu", 
           &dns_bytes[0], &dns_bytes[1], &dns_bytes[2], &dns_bytes[3]);
    memcpy(packet + offset, dns_bytes, 4);
    offset += 4;
    
    // DHCP服务器
    sscanf(DHCP_SERVER, "%hhu.%hhu.%hhu.%hhu", 
           &dns_bytes[0], &dns_bytes[1], &dns_bytes[2], &dns_bytes[3]);
    memcpy(packet + offset, dns_bytes, 4);
    offset += 4;
    
    memset(packet + offset, 0, 12);
    offset += 12;
    
    // Windows版本信息
    packet[offset++] = 0x94;  // OSVersionInfoSize
    memset(packet + offset, 0, 3);
    offset += 3;
    
    packet[offset++] = 0x0a;  // Windows 10 MajorVersion
    memset(packet + offset, 0, 3);
    offset += 3;
    
    memset(packet + offset, 0, 4);  // MinorVersion
    offset += 4;
    
    packet[offset++] = 0x8e;  // BuildNumber (3470)
    packet[offset++] = 0x0d;
    memset(packet + offset, 0, 2);
    offset += 2;
    
    packet[offset++] = 0x02;  // PlatformID (Win32)
    memset(packet + offset, 0, 3);
    offset += 3;
    
    // 操作系统名称
    memcpy(packet + offset, HOST_OS, strlen(HOST_OS));
    offset += strlen(HOST_OS);
    memset(packet + offset, 0, 128 - strlen(HOST_OS));
    offset += 128 - strlen(HOST_OS);
    
    // 认证版本
    unsigned char auth_ver[] = AUTH_VERSION;
    memcpy(packet + offset, auth_ver, 2);
    offset += 2;
    
    packet[offset++] = 0x02;
    packet[offset++] = 0x0c;
    
    // 发送登录请求
    if (sendto(sockfd, packet, offset, 0, 
              (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_msg("[login] Send failed");
        return 0;
    }
    
    log_msg("[login] Sent login request");
    
    // 等待响应
    struct timeval tv = {10, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    for (int i = 0; i < 3; i++) {
        unsigned char response[1024];
        socklen_t addr_len = sizeof(server_addr);
        ssize_t recv_len = recvfrom(sockfd, response, sizeof(response), 0, 
                                   (struct sockaddr*)&server_addr, &addr_len);
        
        if (recv_len > 0 && response[0] == 0x04) {
            memcpy(tail, response + 23, 16);
            log_msg("[login] Login successful");
            return 1;
        } else if (recv_len > 0) {
            log_msg("[login] Unexpected response");
        } else {
            log_msg("[login] Response timeout (%d/3)", i+1);
        }
    }
    
    return 0;
}

// 连接监控器
void* connection_monitor(void* arg) {
    const char* server_ip = (const char*)arg;
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    while (is_running) {
        unsigned char probe_packet[4] = {0x07, 0x00, 0x00, 0x00};
        
        if (sendto(sockfd, probe_packet, sizeof(probe_packet), 0, 
                  (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            log_msg("[monitor] Send probe failed");
        }
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        
        struct timeval timeout = {5, 0};
        int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
            unsigned char response[1024];
            socklen_t addr_len = sizeof(server_addr);
            if (recvfrom(sockfd, response, sizeof(response), 0, 
                        (struct sockaddr*)&server_addr, &addr_len) > 0) {
                log_msg("[monitor] Server active");
            }
        } else {
            log_msg("[monitor] Server unreachable, triggering reconnect");
            reconnect_flag = true;
            break;
        }
        
        sleep(30);  // 每30秒检查一次
    }
    
    return NULL;
}

// 主循环
void main_loop() {
    while (is_running) {
        reconnect_flag = false;
        unsigned char tail[16] = {0};
        
        log_msg("Connecting to %s as %s", SERVER_IP, USERNAME);
        
        if (!login(USERNAME, PASSWORD, SERVER_IP, tail)) {
            log_msg("[main] Login failed, retrying in 30 seconds...");
            sleep(30);
            continue;
        }
        
        memcpy(current_tail, tail, 4);
        log_msg("[main] Login successful");
        
        // 发送初始keep-alive1
        unsigned char salt[4];
        challenge(SERVER_IP, salt);
        send_keep_alive1(salt, current_tail, PASSWORD, SERVER_IP);
        
        // 启动连接监控线程
        pthread_t monitor_thread;
        if (pthread_create(&monitor_thread, NULL, connection_monitor, (void*)SERVER_IP) != 0) {
            log_msg("[main] Failed to create monitor thread");
        } else {
            pthread_detach(monitor_thread);
        }
        
        // 启动自适应心跳
        adaptive_keep_alive((void*)SERVER_IP);
        
        if (reconnect_flag) {
            log_msg("[main] Reconnecting...");
            sleep(5);
        }
    }
}

// 信号处理函数
void signal_handler(int sig) {
    log_msg("Received signal %d, shutting down...", sig);
    is_running = false;
}

// 主函数
int main(int argc, char* argv[]) {
    // 解析命令行参数
    int opt;
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                debug_mode = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    // 初始化随机数生成器
    srand(time(NULL));
    
    // 创建套接字
    sockfd = create_socket();
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    log_msg("=== DRCOM Client Starting ===");
    log_msg("Server: %s, Username: %s", SERVER_IP, USERNAME);
    log_msg("Host IP: %s", HOST_IP);
    
    main_loop();
    
    log_msg("=== DRCOM Client Stopped ===");
    close(sockfd);
    return 0;
}
