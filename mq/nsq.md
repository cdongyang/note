# 特点
1. 服务端程序：nsqd（服务端程序）,nsqlookupq（消费者查找发布者）
2. 客户端访问：http,tcp
3. 分布式可水平拓展，无复制备份
4. 内存存储为主，超出内存存储阀值的消息会存到磁盘，可通过参数--mem-queue-size=0调为硬盘存储
5. 消息无序，传递至少一次（客户端需幂等处理/重复数据删除），可通过客户端滑动窗口实现有序（参考tcp滑动窗口算法）
6. 在流（高吞吐量）和面向工作（低吞吐量）的工作负载方面表现出色
7. topics,channals 独立的消息复制和管理
8. 消息需客户端确认，超时或重新入队会等待客户端重新读取消息，保证只有在nsqd crash的时候才可能丢消息（可通过建立冗余nsqd对缓解）
9. 客户端通过max-in-flight设置批处理消息数量
10. 允许(topic)多播和单播(channel)
11. 提供延时消息，server端优先队列处理
12. push mode
13. 服务端较轻，可跟其它服务部署在一起

单机十万级每秒


特点：高吞吐量，低延时，响应式拉消息
客户端根据当前消费状态调整RDY，发送给服务端之后会触发消息的channal

问题：
1. 如何实现超时重传
2. 如何分发channel消息
3. 