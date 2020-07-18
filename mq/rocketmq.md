在kafka的基础上改进，旨在解决kafka可能出现的高延迟和只用一个分区才能顺序读写所有消息

1. 毫秒级延时
2. 支持严格顺序读写
3. pull mode & push mode
4. 不使用zookeeper，使用nameServer进行注册
5. 0消息丢失
6. 消息发送至少一次，需markMessage另offset+1

https://www.jianshu.com/p/2838890f3284
https://rocketmq.apache.org/docs/motivation/
改进：
支持事务型消息
统一一个commitLog顺序存所有消息，存储在单独broker
每个consumeQueue独立维护自己的offset队列，可分布到多个broker，有指针指向commitLog的位置