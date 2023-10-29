# bugs-sniffer
本次实验主要完成的工作如下：利用c++、libpcap和ncurses以及pthread**开发bugs-sniffer**和**基于wireshark的二次开发**，尝试用libpcap抓DPDK的包。
## BUGS-SNIFFER 功能简介
该工具是基于终端的网络流量嗅探器和分析器，有良好的可扩展性和易用性，实现的功能有：
- [x] 使用`ncurses`和`pthread`进行实时异步地在终端进行结果展示
- [x] 读取设备的所有接口并展示
- [x] 读取设备电源信息并展示
- [x] 读取设备当前时间并展示
- [x] 首页：
	- [x] 实时展示每个接口当前的通过的流量数
	- [x] 展示所有的设备接口，接口名称+地址信息
	- [x] 设置BPF过滤器
	- [x] 读取`pcap`文件
	- [x] 选择设备接口，进入详情页捕获并展示
	- [x] 根据IP和端口进行TCP流跟踪：
		- [x] 使用`BPF`进行流跟踪
		- [x] 使用`hash`表进行流跟踪
	- [x] 根据PID获取当前进程所用的端口号，并进行TCP流跟踪
	- [x] 按下上下键选择接口类型
	- [x] nfqueue
	- [x] 按下f键输入filter、要读取的文件、pid等信息
- [x] 错误页：
	- [x] 提示当前页面大小不符合最低标准，直到用户把页面大小调整到合适的大小
- [x] 详情页：
	- [x] 实时捕获并展示抓到的所有的流量的简略信息
		- [x] 序号、时间戳、src、dst、协议类型、包长和包简介信息
	- [x] 当单个包被选中后展示该包的详情信息，构造该流量包的树形结构（递归分析包）的详细信息，并进行高速缓存
	- [x] 实时展示上行流量和下行流量
	- [x] 异步保存捕获的流量信息，按下s保存
	- [x] 按下空格可以暂停或者继续抓包
- [x] 根据对应的特征递归进行包分析：
	- [x] Ether：src和dst mac addr，ether类型
	- [x] ARP：硬件类型、协议类型、硬件大小、协议大小、opcode、发送者的mac和ip、接收者的mac和ip
	- [x] RARP：硬件类型、协议类型、硬件大小、协议大小、opcode、发送者的mac和ip、接收者的mac和ip
	- [x] VLAN
	- [x] IP：版本，头长、服务类型、总长、id、flags、偏移、ttl、协议类型、checksum、源IP、目标IP
	- [x] IP6：流类型、负载长、下一个头协议类型、hop limit、源IP和目标IP
	- [x] ICMP：类型、代码号、checksum、identifier和序列号
	- [x] TCP：源端口、目标端口、序列号、ack号、数据偏移、flags、窗口大小、checksum、标急位
	- [x] UDP：源端口、目标端口、长度、checksum
	- [x] IGMP：互联网组管理协议
	- [x] TLS：类型、版本
	- [x] HTTP
	- [x] DNS：id、flags、问题数、问题详情
	- [x] DHCP：动态主机配置协议
	- [x] SSDP：简单服务发现协议
	- [x] DTLS：类型
	- [x] STUN：类型
	- [x] QUIC：quick UDP Internet Connections
	- [x] ICMPv6：类型、代码号、checksum、flags
