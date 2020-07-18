1. 所有数据通过磁盘持久化，以append方式写入，实现O(1)开销持久化，定期清除，每个消费组有自己的offset，按写入顺序读区
2. topic可分区到多个kafka server（分布式，可通过加分区提高单topic并发和存储上限），每个kafka server可部署冗余从实例（高可用）
3. topic级订阅广播，consumer group内单播
4. 通过消费组划分分区，实现每个分区在同一个consumer group中只由同一个consumer消费(同一topic并发消费数)，降低排他消费成本
5. 多租户支持，quotas可通过管理API配置
6. 流批处理支持，从一个topic订阅后进行批处理，然后publish到另一个topic
7. 高堆积，支持topic下消费者较长时间离线，消息堆积量大；
8. zookeeper自动负载均衡
9. 高吞吐，在一台普通的服务器上既可以达到10W/s的吞吐速率
10. 单分区实现消息严格有序
11. 毫秒级延时
12. 分区数过多可能照成潜在问题：主备切换时间过长，消息延时过长，consumer/producer批量处理消息时buffer使用内存过多
13. pull mode
14. 消息发送至少一次，需markMessage另offset+1

https://www.confluent.io/blog/how-choose-number-topics-partitions-kafka-cluster/
https://engineering.linkedin.com/kafka/benchmarking-apache-kafka-2-million-writes-second-three-cheap-machines
https://rocketmq.apache.org/rocketmq/how-to-support-more-queues-in-rocketmq/
使用场景：
1. 消息队列（用于解耦或缓存消息）
2. 网站活动数据pipeline
3. monitor metric
4. 日志领域（重点）
5. 流处理，汇总数据，处理完再publish出去