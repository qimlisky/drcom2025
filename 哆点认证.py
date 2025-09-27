#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import time
import hashlib
import sys
import os
import random
import traceback
import binascii
import threading
import select

# CONFIG
server = '对应内容'
username = '账号'
password = '密码'
CONTROLCHECKSTATUS = b'对应内容'
ADAPTERNUM = b'对应内容'
host_ip = '插入网线获取的ip'
IPDOG = b'对应内容'
host_name = '对应内容'
PRIMARY_DNS = '对应内容'
dhcp_server = '对应内容'
AUTH_VERSION = b'对应内容'
mac = 0x对应内容
host_os = 'Windows 10'
KEEP_ALIVE_VERSION = b'对应内容'
ror_version = False
# CONFIG_END
#对应内容（汉字）和插入网线获取的ip（汉字）改实际内容
# 全局状态
is_running = True
last_keepalive_time = time.time()
keepalive_counter = 0
current_tail = b''
reconnect_flag = False

# 创建UDP套接字
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 61440))
s.settimeout(10)

# 日志配置
DEBUG = True
LOG_PATH = 'drcom_client.log'

def log(*args, **kwargs):
    """增强型日志函数，带时间戳和日志级别"""
    message = ' '.join(str(arg) for arg in args)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_level = "INFO"
    if "WARNING" in message or "timeout" in message:
        log_level = "WARN"
    elif "ERROR" in message or "Failed" in message:
        log_level = "ERROR"
    
    formatted = f"[{timestamp}] [{log_level}] {message}"
    print(formatted)
    if DEBUG:
        with open(LOG_PATH, 'a') as f:
            f.write(formatted + "\n")

def challenge(svr):
    """获取挑战值，优化重试逻辑"""
    attempts = 0
    while attempts < 5 and is_running:
        try:
            t = struct.pack("<H", random.randint(0, 0xFFFF))
            packet = b'\x01\x02' + t + b'\x09' + b'\x00' * 15
            s.sendto(packet, (svr, 61440))
            
            data, address = s.recvfrom(1024)
            if address == (svr, 61440) and data[0] == 0x02:
                log(f'[challenge] Success, salt: {binascii.hexlify(data[4:8])}')
                return data[4:8]
        except socket.timeout:
            log('[challenge] Timeout, retrying...')
        except Exception as e:
            log(f'[challenge] Error: {str(e)}')
        
        attempts += 1
        time.sleep(2)
    
    log('[challenge] Failed after 5 attempts')
    return None

def md5sum(s):
    """计算MD5哈希值"""
    m = hashlib.md5()
    m.update(s)
    return m.digest()

def keep_alive_packet(number, pkg_type, tail, counter=None):
    """构建keep-alive数据包，优化类型3包结构"""
    packet = b'\x07' + bytes([number]) + b'\x28\x00\x0b' + bytes([pkg_type])
    
    if pkg_type == 1:  # 心跳包类型1
        packet += KEEP_ALIVE_VERSION
        packet += b'\x2f\x12' + b'\x00' * 6
        packet += tail
        packet += b'\x00' * 4
        # 添加主机IP地址
        ip_bytes = bytes(map(int, host_ip.split('.')))
        packet += b'\x00' * 12  # 空白填充
        packet += ip_bytes
    
    elif pkg_type == 3:  # 心跳包类型3
        packet += b'\x0f\x27'  # 特殊版本标记
        packet += b'\x2f\x12' + b'\x00' * 6
        packet += tail
        packet += b'\x00' * 4
        
        # 添加IP地址和校验
        ip_bytes = bytes(map(int, host_ip.split('.')))
        # 计算简化CRC
        crc = hashlib.md5(ip_bytes).digest()[:4]
        packet += crc
        packet += ip_bytes
        packet += b'\x00' * 8
    
    # 添加计数器（如果提供）
    if counter is not None:
        packet += counter.to_bytes(4, 'big')
    
    return packet

def adaptive_keep_alive(svr, tail):
    """自适应心跳机制，根据网络状况调整间隔"""
    global keepalive_counter, last_keepalive_time, current_tail, reconnect_flag
    
    seq_num = 1
    failures = 0
    base_interval = 25  # 基础心跳间隔
    min_interval = 15   # 最小间隔
    max_interval = 45   # 最大间隔
    current_interval = base_interval
   ##看这里！！！！！！！！！！！！！！！！！！！！！！！！！！！！！ 
    while is_running and not reconnect_flag:
        try:
            # 动态调整心跳间隔
            elapsed = time.time() - last_keepalive_time
            if elapsed < current_interval:
                time.sleep(current_interval - elapsed)
                continue
            
            last_keepalive_time = time.time()
            keepalive_counter += 1
            
            # 发送类型1心跳包
            packet1 = keep_alive_packet(seq_num, 1, tail, keepalive_counter)
            s.sendto(packet1, (svr, 61440))
            log(f'[keep-alive] Sent type1 packet #{seq_num}, interval: {current_interval}s')
            
            # 设置较短超时等待响应
            s.settimeout(8)
            try:
                data, addr = s.recvfrom(1024)
                if data[0] == 0x07:
                    new_tail = data[16:20]
                    if new_tail:
                        tail = new_tail
                        current_tail = tail
                        log(f'[keep-alive] Received response, new tail: {binascii.hexlify(tail)}')
                    
                    # 响应成功，重置失败计数并增加间隔
                    failures = 0
                    current_interval = min(current_interval + 2, max_interval)
                else:
                    log(f'[keep-alive] Unexpected response: {binascii.hexlify(data)}')
                    failures += 1
            except socket.timeout:
                log('[keep-alive] Type1 response timeout')
                failures += 1
                # 响应超时，缩短心跳间隔
                current_interval = max(current_interval - 5, min_interval)
            
            # 每3次心跳发送一次类型3心跳包
            if keepalive_counter % 3 == 0:
                seq_num = (seq_num + 1) % 256
                packet3 = keep_alive_packet(seq_num, 3, tail, keepalive_counter)
                s.sendto(packet3, (svr, 61440))
                log(f'[keep-alive] Sent type3 packet #{seq_num}')
                
                try:
                    data, addr = s.recvfrom(1024)
                    if data[0] == 0x07:
                        new_tail = data[16:20]
                        if new_tail:
                            tail = new_tail
                            current_tail = tail
                        failures = 0
                    else:
                        log(f'[keep-alive] Unexpected type3 response: {binascii.hexlify(data)}')
                except socket.timeout:
                    log('[keep-alive] Type3 response timeout')
            
            # 失败处理
            if failures >= 2:
                log('[keep-alive] Too many failures, re-authenticating...')
                reconnect_flag = True
                return
            
            seq_num = (seq_num + 1) % 256
            
        except Exception as e:
            log(f'[keep-alive] Error: {str(e)}')
            log(traceback.format_exc())
            failures += 1
            time.sleep(5)
    
    return

def send_keep_alive1(salt, tail, pwd, svr):
    """发送keep-alive1包，优化重试逻辑"""
    try:
        foo = struct.pack('!H', int(time.time()) % 0xFFFF)
        data = b'\xff' + md5sum(b'\x03\x01' + salt + pwd.encode()) + b'\x00\x00\x00'
        data += tail
        data += foo + b'\x00\x00\x00\x00'
        
        s.sendto(data, (svr, 61440))
        log('[keep-alive1] Sent')
        
        # 等待响应，最多3秒
        s.settimeout(3)
        try:
            resp, addr = s.recvfrom(1024)
            log('[keep-alive1] Received response')
        except socket.timeout:
            log('[keep-alive1] Response timeout, continuing...')
        
        return True
        
    except Exception as e:
        log(f'[keep-alive1] Error: {str(e)}')
        return False

def login(usr, pwd, svr):
    """登录认证，优化MAC地址处理"""
    salt = challenge(svr)
    if not salt:
        log('[login] Failed to get challenge salt')
        return None
    
    # 构建登录包
    packet = b'\x03\x01\x00' + bytes([len(usr) + 20])
    packet += md5sum(b'\x03\x01' + salt + pwd.encode())
    packet += usr.encode().ljust(36, b'\x00')
    packet += CONTROLCHECKSTATUS
    packet += ADAPTERNUM
    
    # MAC地址处理 - 优化兼容性
    mac_bytes = mac.to_bytes(6, 'big')
    mac_xor = bytes([packet[4+i] ^ mac_bytes[i] for i in range(6)])
    packet += mac_xor
    
    packet += md5sum(b'\x01' + pwd.encode() + salt + b'\x00' * 4)
    packet += b'\x01' + bytes(map(int, host_ip.split('.')))
    packet += b'\x00' * 12
    packet += md5sum(packet + b'\x14\x00\x07\x0B')[:8]
    packet += IPDOG + b'\x00' * 4
    
    # 主机信息 - 优化Windows版本信息
    packet += host_name.encode().ljust(32, b'\x00')
    packet += bytes(map(int, PRIMARY_DNS.split('.')))
    packet += bytes(map(int, dhcp_server.split('.')))
    packet += b'\x00' * 12
    packet += b'\x94\x00\x00\x00'  # OSVersionInfoSize
    packet += b'\x0A\x00\x00\x00'  # Windows 10 MajorVersion (10)
    packet += b'\x00\x00\x00\x00'  # MinorVersion
    packet += b'\x8E\x0D\x00\x00'  # BuildNumber (3470)
    packet += b'\x02\x00\x00\x00'  # PlatformID (Win32)
    packet += host_os.encode().ljust(128, b'\x00')
    packet += AUTH_VERSION + b'\x02\x0c'
    
    # 校验和 - 优化算法
    crc_data = packet + b'\x01\x26\x07\x11\x00\x00' + mac_bytes
    checksum_val = 0x1234
    for i in range(0, len(crc_data), 4):
        chunk = crc_data[i:i+4].ljust(4, b'\x00')
        checksum_val ^= struct.unpack('<I', chunk)[0]
    checksum_val = (checksum_val * 0x2C7) & 0xFFFFFFFF
    packet += struct.pack('<I', checksum_val)
    
    packet += b'\x00\x00' + mac_bytes + b'\x00\x00\xE9\x13'
    
    # 发送登录请求
    s.sendto(packet, (svr, 61440))
    log('[login] Sent login request')
    
    # 等待响应，增加超时重试
    for i in range(3):
        try:
            data, addr = s.recvfrom(1024)
            if data[0] == 0x04:
                log('[login] Login successful')
                return data[23:39]  # 返回tail
            else:
                log(f'[login] Unexpected response: {binascii.hexlify(data)}')
        except socket.timeout:
            log(f'[login] Response timeout ({i+1}/3)')
    
    return None

def connection_monitor(svr):
    """增强型连接状态监控器"""
    global is_running, reconnect_flag
    
    while is_running:
        try:
            # 测试服务器可达性 - 使用更可靠的方法
            s.sendto(b'\x07\x00\x00\x00', (svr, 61440))
            ready = select.select([s], [], [], 5)
            if ready[0]:
                data, addr = s.recvfrom(1024)
                log(f'[monitor] Server active, response: {binascii.hexlify(data[:4])}')
            else:
                log('[monitor] Server unreachable, triggering reconnect')
                reconnect_flag = True
                return
            
            time.sleep(30)  # 每30秒检查一次!!!!!!!!!!!!!!!
            
        except Exception as e:
            log(f'[monitor] Error: {str(e)}')
            reconnect_flag = True
            return

def main_loop():
    """主循环，优化重连逻辑"""
    global is_running, reconnect_flag, current_tail
    
    while True:
        try:
            is_running = True
            reconnect_flag = False
            
            # 登录认证
            log(f"Connecting to {server} as {username}")
            tail = login(username, password, server)
            if not tail:
                log('[main] Login failed, retrying in 30 seconds...')
                time.sleep(30)
                continue
            
            current_tail = tail
            log(f'[main] Login successful, tail: {binascii.hexlify(tail)}')
            
            # 发送初始keep-alive1
            salt = challenge(server) or b''
            send_keep_alive1(salt, tail, password, server)
            
            # 启动连接监控线程
            monitor_thread = threading.Thread(target=connection_monitor, args=(server,))
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # 启动自适应心跳
            adaptive_keep_alive(server, tail)
            
            # 如果心跳结束，检查是否需要重连
            if reconnect_flag:
                log('[main] Reconnecting...')
                time.sleep(5)
                continue
            
        except KeyboardInterrupt:
            log('[main] Shutdown by user request')
            is_running = False
            break
        except Exception as e:
            log(f'[main] Critical error: {str(e)}')
            log(traceback.format_exc())
            time.sleep(10)
        finally:
            is_running = False
            if reconnect_flag:
                log('[main] Reconnecting after 5 seconds...')
                time.sleep(5)
                reconnect_flag = False

if __name__ == "__main__":
    log("=== DRCOM Client Starting ===")
    log(f"Server: {server}, Username: {username}")
    log(f"Host IP: {host_ip}, MAC: {hex(mac)}")
    
    main_loop()
    
    log("=== DRCOM Client Stopped ===")
