实现一个udp forwarder，把client上的一个udp server port转发到server上，server listen，然后转发给client。client是一个nat后的机器。

# 协议设计

server和client配置文件里面有一个pre shared key，其kdf结果为hmac的key。

server listen 2个udp端口

第一个端口是控制端口，client发送0x00加上当前时间戳，和当前时间戳的hmac。server收到后，验证hmac和时间戳（要求在1分钟以内）把这个udp端口作为跟client通信的端口，并回一个0x02的ack（回显client时间戳+server时间戳+hmac）。client每30秒发一次握手作为心跳，用来刷新nat映射并确认链路存活。

第二个端口是数据端口。互联网上的客户端正常发送packet到这个端口。server把这个payload加上48bit的ipv4地址+端口号header，发送给client通信端口。client用127.0.0.1模拟不同的客户端，跟本地的udp service通讯，然后把udp server返回的结果加上0x01和48bit的ipv4地址+端口号header，发动给server的控制端口，server转发经过数据端口返回给互联网上的客户端。

控制端口上每个报文第一个字节是类型，所以server发给client的数据报文同样带0x01前缀（0x01 + 48bit header + payload），以便和0x02的ack区分。

client需要维护一个127.0.0.1端口 到 ipv4+端口 的映射。2分钟不活跃的端口要清除掉映射。

只需要支持ipv4

# 要求

纯C
网络只用epoll
密码库只用libsodium
配置文件用ini
静态链接，libc用musl
libsodium用源码编译成静态库。



