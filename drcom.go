package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// 配置参数（修改下面小部分）
var (
	server      = ""
	username    = "账号"
	password    = "密码"
	hostIP      = "" // 默认主机IP
	hostName    = ""
	primaryDNS  = ""
	dhcpServer  = ""
	macAddr     = ""
	//MAC地址为aa：bb：cc……
	hostOS      = "Windows 10"
	verbose     bool
)

// 全局状态
var (
	isRunning         bool
	lastKeepaliveTime time.Time
	keepaliveCounter  uint32
	currentTail       []byte
	reconnectFlag     bool
	conn              *net.UDPConn
	serverAddr        *net.UDPAddr
	mu                sync.Mutex
)

func init() {
	// 解析命令行参数
	flag.StringVar(&server, "s", server, "服务器地址")
	flag.StringVar(&username, "u", username, "用户名")
	flag.StringVar(&password, "p", password, "密码")
	flag.StringVar(&hostIP, "i", hostIP, "主机IP地址") // 添加 -i 参数
	flag.BoolVar(&verbose, "v", false, "详细日志输出")
	flag.Parse()
	
	// 初始化随机种子
	rand.Seed(time.Now().UnixNano())
}

func logMessage(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLevel := "INFO"
	
	// 根据消息内容确定日志级别
	if verbose {
		fmt.Printf("[%s] [%s] %s\n", timestamp, logLevel, msg)
	}
	log.Printf("[%s] [%s] %s\n", timestamp, logLevel, msg)
}

func challenge() ([]byte, error) {
	for attempts := 0; attempts < 5 && isRunning; attempts++ {
		t := make([]byte, 2)
		binary.LittleEndian.PutUint16(t, uint16(rand.Intn(0xFFFF)))
		
		packet := []byte{0x01, 0x02}
		packet = append(packet, t...)
		packet = append(packet, 0x09)
		packet = append(packet, make([]byte, 15)...)
		
		_, err := conn.WriteToUDP(packet, serverAddr)
		if err != nil {
			logMessage("[challenge] 发送失败: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		
		// 设置超时
		err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			logMessage("[challenge] 设置超时失败: %v", err)
			continue
		}
		
		buffer := make([]byte, 1024)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logMessage("[challenge] 接收失败: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		
		if addr.String() != serverAddr.String() {
			logMessage("[challenge] 收到非服务器响应")
			continue
		}
		
		data := buffer[:n]
		if data[0] == 0x02 && n >= 8 {
			salt := data[4:8]
			logMessage("[challenge] 成功, salt: %s", hex.EncodeToString(salt))
			return salt, nil
		}
		
		logMessage("[challenge] 收到无效响应: %s", hex.EncodeToString(data))
		time.Sleep(2 * time.Second)
	}
	
	return nil, fmt.Errorf("challenge 失败")
}

func md5Sum(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

func keepAlivePacket(number uint8, pkgType uint8, tail []byte) []byte {
	packet := []byte{0x07, number, 0x28, 0x00, 0x0b, pkgType}
	
	switch pkgType {
	case 1:
		packet = append(packet, []byte("undefined")...)
		packet = append(packet, []byte{0x2f, 0x12}...)
		packet = append(packet, make([]byte, 6)...)
		packet = append(packet, tail...)
		packet = append(packet, make([]byte, 4)...)
		
		// 添加主机IP地址
		ip := net.ParseIP(hostIP).To4()
		packet = append(packet, make([]byte, 12)...)
		packet = append(packet, ip...)
	
	case 3:
		packet = append(packet, []byte{0x0f, 0x27}...)
		packet = append(packet, []byte{0x2f, 0x12}...)
		packet = append(packet, make([]byte, 6)...)
		packet = append(packet, tail...)
		packet = append(packet, make([]byte, 4)...)
		
		// 添加IP地址和校验
		ip := net.ParseIP(hostIP).To4()
		crc := md5Sum(ip)[:4]
		packet = append(packet, crc...)
		packet = append(packet, ip...)
		packet = append(packet, make([]byte, 8)...)
	}
	
	// 添加计数器
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, keepaliveCounter)
	packet = append(packet, counterBytes...)
	
	return packet
}

func adaptiveKeepAlive(tail []byte) {
	baseInterval := 25
	minInterval := 15
	maxInterval := 45
	currentInterval := baseInterval
	seqNum := uint8(1)
	failures := 0
	
	for isRunning && !reconnectFlag {
		mu.Lock()
		elapsed := time.Since(lastKeepaliveTime)
		if elapsed < time.Duration(currentInterval)*time.Second {
			mu.Unlock()
			time.Sleep(time.Duration(currentInterval)*time.Second - elapsed)
			continue
		}
		
		lastKeepaliveTime = time.Now()
		keepaliveCounter++
		mu.Unlock()
		
		// 发送类型1心跳包
		packet := keepAlivePacket(seqNum, 1, tail)
		_, err := conn.WriteToUDP(packet, serverAddr)
		if err != nil {
			logMessage("[keep-alive] 发送失败: %v", err)
			failures++
			time.Sleep(5 * time.Second)
			continue
		}
		
		logMessage("[keep-alive] 发送 type1 包 #%d, 间隔: %ds", seqNum, currentInterval)
		
		// 设置超时等待响应
		conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		buffer := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logMessage("[keep-alive] 接收响应超时")
			failures++
			currentInterval = max(minInterval, currentInterval-5)
		} else {
			data := buffer[:n]
			if data[0] == 0x07 && len(data) >= 20 {
				newTail := data[16:20]
				if len(newTail) > 0 {
					tail = newTail
					mu.Lock()
					currentTail = newTail
					mu.Unlock()
					logMessage("[keep-alive] 收到响应, new tail: %s", hex.EncodeToString(newTail))
				}
				failures = 0
				currentInterval = min(maxInterval, currentInterval+2)
			} else {
				logMessage("[keep-alive] 收到无效响应: %s", hex.EncodeToString(data))
				failures++
			}
		}
		
		// 每3次心跳发送一次类型3心跳包
		if keepaliveCounter%3 == 0 {
			seqNum = (seqNum % 255) + 1
			packet3 := keepAlivePacket(seqNum, 3, tail)
			_, err := conn.WriteToUDP(packet3, serverAddr)
			if err != nil {
				logMessage("[keep-alive] 发送 type3 失败: %v", err)
			} else {
				logMessage("[keep-alive] 发送 type3 包 #%d", seqNum)
			}
			
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _, err = conn.ReadFromUDP(buffer)
			if err != nil {
				logMessage("[keep-alive] type3 响应超时")
			}
		}
		
		if failures >= 2 {
			logMessage("[keep-alive] 失败过多, 重新认证...")
			reconnectFlag = true
			return
		}
		
		seqNum = (seqNum % 255) + 1
	}
}

func sendKeepAlive1(salt, tail []byte) error {
	timestamp := uint16(time.Now().Unix() % 0xFFFF)
	foo := make([]byte, 2)
	binary.BigEndian.PutUint16(foo, timestamp)
	
	data := []byte{0xff}
	data = append(data, md5Sum([]byte{0x03, 0x01})...)
	data = append(data, salt...)
	data = append(data, []byte{0x00, 0x00, 0x00}...)
	data = append(data, tail...)
	data = append(data, foo...)
	data = append(data, make([]byte, 4)...)
	
	_, err := conn.WriteToUDP(data, serverAddr)
	if err != nil {
		return fmt.Errorf("发送 keep-alive1 失败: %v", err)
	}
	
	logMessage("[keep-alive1] 已发送")
	
	// 设置超时等待响应
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	_, _, err = conn.ReadFromUDP(buffer)
	if err != nil {
		logMessage("[keep-alive1] 响应超时")
	}
	
	return nil
}

func login() ([]byte, error) {
	salt, err := challenge()
	if err != nil {
		return nil, fmt.Errorf("获取挑战值失败: %v", err)
	}
	
	packet := []byte{0x03, 0x01, 0x00, byte(len(username) + 20)}
	packet = append(packet, md5Sum(append([]byte{0x03, 0x01}, append(salt, []byte(password)...)...))...)
	
	// 添加用户名
	usernameBytes := []byte(username)
	if len(usernameBytes) > 36 {
		usernameBytes = usernameBytes[:36]
	} else {
		usernameBytes = append(usernameBytes, make([]byte, 36-len(usernameBytes))...)
	}
	packet = append(packet, usernameBytes...)
	
	// 添加控制检查状态和适配器编号
	packet = append(packet, 0x20, 0x07)
	
	// 解析MAC地址
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return nil, fmt.Errorf("解析MAC地址失败: %v", err)
	}
	
	// MAC地址异或处理
	macXor := make([]byte, 6)
	for i := 0; i < 6; i++ {
		if i < len(packet) {
			macXor[i] = packet[4+i] ^ mac[i]
		}
	}
	packet = append(packet, macXor...)
	
	// 添加更多认证数据
	authData := append([]byte{0x01}, append([]byte(password), append(salt, make([]byte, 4)...)...)...)
	packet = append(packet, md5Sum(authData)...)
	
	// 添加主机IP
	ip := net.ParseIP(hostIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("无效的IP地址: %s", hostIP)
	}
	packet = append(packet, 0x01)
	packet = append(packet, ip...)
	packet = append(packet, make([]byte, 12)...)
	
	// 添加更多校验数据
	checkData := append(packet, []byte{0x14, 0x00, 0x07, 0x0B}...)
	packet = append(packet, md5Sum(checkData)[:8]...)
	
	// 添加IPDOG和空白
	packet = append(packet, 0x01)
	packet = append(packet, make([]byte, 4)...)
	
	// 添加主机名
	hostNameBytes := []byte(hostName)
	if len(hostNameBytes) > 32 {
		hostNameBytes = hostNameBytes[:32]
	} else {
		hostNameBytes = append(hostNameBytes, make([]byte, 32-len(hostNameBytes))...)
	}
	packet = append(packet, hostNameBytes...)
	
	// 添加DNS和DHCP服务器
	dnsIP := net.ParseIP(primaryDNS).To4()
	if dnsIP == nil {
		return nil, fmt.Errorf("无效的DNS地址: %s", primaryDNS)
	}
	packet = append(packet, dnsIP...)
	
	dhcpIP := net.ParseIP(dhcpServer).To4()
	if dhcpIP == nil {
		return nil, fmt.Errorf("无效的DHCP地址: %s", dhcpServer)
	}
	packet = append(packet, dhcpIP...)
	
	// 添加空白
	packet = append(packet, make([]byte, 12)...)
	
	// 添加操作系统信息
	packet = append(packet, []byte{0x94, 0x00, 0x00, 0x00}...) // OSVersionInfoSize
	packet = append(packet, []byte{0x0A, 0x00, 0x00, 0x00}...) // MajorVersion (10)
	packet = append(packet, []byte{0x00, 0x00, 0x00, 0x00}...) // MinorVersion
	packet = append(packet, []byte{0x8E, 0x0D, 0x00, 0x00}...) // BuildNumber (3470)
	packet = append(packet, []byte{0x02, 0x00, 0x00, 0x00}...) // PlatformID (Win32)
	
	// 添加操作系统名称
	osBytes := []byte(hostOS)
	if len(osBytes) > 128 {
		osBytes = osBytes[:128]
	} else {
		osBytes = append(osBytes, make([]byte, 128-len(osBytes))...)
	}
	packet = append(packet, osBytes...)
	
	// 添加认证版本
	packet = append(packet, []byte{0x2c, 0x00, 0x02, 0x0c}...)
	
	// 计算校验和
	crcData := append(packet, []byte{0x01, 0x26, 0x07, 0x11, 0x00, 0x00}...)
	crcData = append(crcData, mac...)
	
	checksum := uint32(0x1234)
	for i := 0; i < len(crcData); i += 4 {
		var chunk uint32
		if i+4 <= len(crcData) {
			chunk = binary.LittleEndian.Uint32(crcData[i : i+4])
		} else {
			remaining := crcData[i:]
			padded := make([]byte, 4)
			copy(padded, remaining)
			chunk = binary.LittleEndian.Uint32(padded)
		}
		checksum ^= chunk
	}
	checksum = (checksum * 0x2C7) & 0xFFFFFFFF
	
	checksumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumBytes, checksum)
	packet = append(packet, checksumBytes...)
	
	// 添加MAC地址和结束标志
	packet = append(packet, []byte{0x00, 0x00}...)
	packet = append(packet, mac...)
	packet = append(packet, []byte{0x00, 0x00, 0xE9, 0x13}...)
	
	// 发送登录请求
	_, err = conn.WriteToUDP(packet, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("发送登录请求失败: %v", err)
	}
	
	logMessage("[login] 登录请求已发送")
	
	// 等待响应
	for i := 0; i < 3; i++ {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buffer := make([]byte, 1024)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logMessage("[login] 接收响应失败 (%d/3): %v", i+1, err)
			continue
		}
		
		if addr.String() != serverAddr.String() {
			logMessage("[login] 收到非服务器响应")
			continue
		}
		
		data := buffer[:n]
		if data[0] == 0x04 && n >= 39 {
			tail := data[23:39]
			logMessage("[login] 登录成功, tail: %s", hex.EncodeToString(tail))
			return tail, nil
		}
		
		logMessage("[login] 收到无效响应: %s", hex.EncodeToString(data))
	}
	
	return nil, fmt.Errorf("登录失败")
}

func connectionMonitor() {
	for isRunning {
		// 测试服务器可达性
		_, err := conn.WriteToUDP([]byte{0x07, 0x00, 0x00, 0x00}, serverAddr)
		if err != nil {
			logMessage("[monitor] 发送探测包失败: %v", err)
			reconnectFlag = true
			return
		}
		
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 1024)
		_, _, err = conn.ReadFromUDP(buffer)
		if err != nil {
			logMessage("[monitor] 服务器不可达, 触发重连")
			reconnectFlag = true
			return
		}
		
		logMessage("[monitor] 服务器活跃")
		time.Sleep(30 * time.Second)
	}
}

func mainLoop() {
	for {
		isRunning = true
		reconnectFlag = false
		
		logMessage("=== 连接服务器 %s 用户 %s ===", server, username)
		logMessage("主机IP: %s, MAC: %s", hostIP, macAddr)
		
		// 登录认证
		tail, err := login()
		if err != nil {
			logMessage("[main] 登录失败: %v, 30秒后重试...", err)
			time.Sleep(30 * time.Second)
			continue
		}
		
		mu.Lock()
		currentTail = tail
		mu.Unlock()
		
		// 发送初始keep-alive1
		salt, err := challenge()
		if err == nil {
			sendKeepAlive1(salt, tail)
		}
		
		// 启动连接监控
		go connectionMonitor()
		
		// 启动自适应心跳
		adaptiveKeepAlive(tail)
		
		if reconnectFlag {
			logMessage("[main] 重新连接...")
			time.Sleep(5 * time.Second)
			continue
		}
		
		logMessage("[main] 连接意外终止, 10秒后重试...")
		time.Sleep(10 * time.Second)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	// 设置日志
	logFile, err := os.OpenFile("drcom_client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	
	// 解析服务器地址
	udpAddr, err := net.ResolveUDPAddr("udp4", server+":61440")
	if err != nil {
		log.Fatalf("解析服务器地址失败: %v", err)
	}
	serverAddr = udpAddr
	
	// 创建UDP连接
	localAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:61440")
	if err != nil {
		log.Fatalf("解析本地地址失败: %v", err)
	}
	
	conn, err = net.ListenUDP("udp4", localAddr)
	if err != nil {
		log.Fatalf("创建UDP连接失败: %v", err)
	}
	defer conn.Close()
	
	// 设置超时
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	// 处理信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logMessage("=== 用户请求关闭 ===")
		isRunning = false
		conn.Close()
		os.Exit(0)
	}()
	
	logMessage("=== DRCOM 客户端启动 ===")
	logMessage("服务器: %s, 用户: %s", server, username)
	logMessage("主机IP: %s, MAC: %s", hostIP, macAddr)
	
	mainLoop()
}
