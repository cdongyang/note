# consumer

## main example
```go
func main() {
	cfg := nsq.NewConfig()
	consumer, err := nsq.NewConsumer("topic-a", "channal-a", cfg)
	if err != nil {
		log.Fatal(err)
	}
	consumer.AddConcurrentHandlers(nsq.HandlerFunc(func(message *nsq.Message) error {
		var deal string
		if rand.Intn(2) == -1 {
			message.Requeue(time.Second)
			deal = "requeue"
		} else {
			message.Finish()
			deal = "finish"
		}
		log.Printf("%s %v %s %s %v %v\n", deal, message.Attempts, message.Body, message.ID, message.NSQDAddress, message.Timestamp)
		return nil
	}), 1000)
	if err = consumer.ConnectToNSQLookupds([]string{"localhost:4161", "localhost:3161", "localhost:2161"}); err != nil {
		log.Fatal(err)
	}
	<-consumer.StopChan
}
// AddConcurrentHandlers sets the Handler for messages received by this Consumer.  It
// takes a second argument which indicates the number of goroutines to spawn for
// message handling.
//
// This panics if called after connecting to NSQD or NSQ Lookupd
//
// (see Handler or HandlerFunc for details on implementing this interface)
func (r *Consumer) AddConcurrentHandlers(handler Handler, concurrency int) {
	if atomic.LoadInt32(&r.connectedFlag) == 1 {
		panic("already connected")
	}

	atomic.AddInt32(&r.runningHandlers, int32(concurrency))
	for i := 0; i < concurrency; i++ {
		go r.handlerLoop(handler) // 多个Consumer并行从r.incomingMessages里面读消息并处理
	}
}

```
```go
// After Config is passed into NewConsumer the values are no longer mutable (they are copied).
func NewConsumer(topic string, channel string, config *Config) (*Consumer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if !IsValidTopicName(topic) {
		return nil, errors.New("invalid topic name")
	}

	if !IsValidChannelName(channel) {
		return nil, errors.New("invalid channel name")
	}

	r := &Consumer{
		id: atomic.AddInt64(&instCount, 1),

		topic:   topic,
		channel: channel,
		config:  *config,

		logger:      make([]logger, LogLevelMax+1),
		logLvl:      LogLevelInfo,
		maxInFlight: int32(config.MaxInFlight),

		incomingMessages: make(chan *Message),

		rdyRetryTimers:     make(map[string]*time.Timer),
		pendingConnections: make(map[string]*Conn),
		connections:        make(map[string]*Conn),

		lookupdRecheckChan: make(chan int, 1),

		rng: rand.New(rand.NewSource(time.Now().UnixNano())),

		StopChan: make(chan int),
		exitChan: make(chan int),
	}

	// Set default logger for all log levels
	l := log.New(os.Stderr, "", log.Flags())
	for index := range r.logger {
		r.logger[index] = l
	}

	r.wg.Add(1)
	go r.rdyLoop()
	return r, nil
}
```
## rdyLoop
```go
func (r *Consumer) rdyLoop() {
	redistributeTicker := time.NewTicker(r.config.RDYRedistributeInterval)

	for {
		select {
		case <-redistributeTicker.C: // 定时发送rdy
			r.redistributeRDY()
		case <-r.exitChan:
			goto exit
		}
	}

exit:
	redistributeTicker.Stop()
	r.log(LogLevelInfo, "rdyLoop exiting")
	r.wg.Done()
}
func (r *Consumer) redistributeRDY() {
	if r.inBackoffTimeout() {
		return
	}

	// if an external heuristic set needRDYRedistributed we want to wait
	// until we can actually redistribute to proceed
	conns := r.conns()
	if len(conns) == 0 {
		return
	}

	maxInFlight := r.getMaxInFlight()
	if len(conns) > int(maxInFlight) {
		r.log(LogLevelDebug, "redistributing RDY state (%d conns > %d max_in_flight)",
			len(conns), maxInFlight)
		atomic.StoreInt32(&r.needRDYRedistributed, 1)
	}

	if r.inBackoff() && len(conns) > 1 {
		r.log(LogLevelDebug, "redistributing RDY state (in backoff and %d conns > 1)", len(conns))
		atomic.StoreInt32(&r.needRDYRedistributed, 1)
	}

	if !atomic.CompareAndSwapInt32(&r.needRDYRedistributed, 1, 0) {
		return
	}

	possibleConns := make([]*Conn, 0, len(conns))
	for _, c := range conns {
		lastMsgDuration := time.Now().Sub(c.LastMessageTime())
		lastRdyDuration := time.Now().Sub(c.LastRdyTime())
		rdyCount := c.RDY()
		r.log(LogLevelDebug, "(%s) rdy: %d (last message received %s)",
			c.String(), rdyCount, lastMsgDuration)
		if rdyCount > 0 {
			if lastMsgDuration > r.config.LowRdyIdleTimeout {
				r.log(LogLevelDebug, "(%s) idle connection, giving up RDY", c.String())
				r.updateRDY(c, 0)
			} else if lastRdyDuration > r.config.LowRdyTimeout {
				r.log(LogLevelDebug, "(%s) RDY timeout, giving up RDY", c.String())
				r.updateRDY(c, 0)
			}
		}
		possibleConns = append(possibleConns, c)
	}

	availableMaxInFlight := int64(maxInFlight) - atomic.LoadInt64(&r.totalRdyCount)
	if r.inBackoff() {
		availableMaxInFlight = 1 - atomic.LoadInt64(&r.totalRdyCount)
	}

	for len(possibleConns) > 0 && availableMaxInFlight > 0 {
		availableMaxInFlight--
		r.rngMtx.Lock()
		i := r.rng.Int() % len(possibleConns)
		r.rngMtx.Unlock()
		c := possibleConns[i]
		// delete
		possibleConns = append(possibleConns[:i], possibleConns[i+1:]...)
		r.log(LogLevelDebug, "(%s) redistributing RDY", c.String())
		r.updateRDY(c, 1)
	}
}

```

```go
// ConnectToNSQLookupds adds multiple nsqlookupd address to the list for this Consumer instance.
//
// If adding the first address it initiates an HTTP request to discover nsqd
// producers for the configured topic.
//
// A goroutine is spawned to handle continual polling.
func (r *Consumer) ConnectToNSQLookupds(addresses []string) error {
	for _, addr := range addresses {
		err := r.ConnectToNSQLookupd(addr)
		if err != nil {
			return err
		}
	}
	return nil
}
// ConnectToNSQLookupd adds an nsqlookupd address to the list for this Consumer instance.
//
// If it is the first to be added, it initiates an HTTP request to discover nsqd
// producers for the configured topic.
//
// A goroutine is spawned to handle continual polling.
func (r *Consumer) ConnectToNSQLookupd(addr string) error {
	if atomic.LoadInt32(&r.stopFlag) == 1 {
		return errors.New("consumer stopped")
	}
	if atomic.LoadInt32(&r.runningHandlers) == 0 {
		return errors.New("no handlers")
	}

	if err := validatedLookupAddr(addr); err != nil {
		return err
	}

	atomic.StoreInt32(&r.connectedFlag, 1)

	r.mtx.Lock()
	for _, x := range r.lookupdHTTPAddrs {
		if x == addr {
			r.mtx.Unlock()
			return nil
		}
	}
	r.lookupdHTTPAddrs = append(r.lookupdHTTPAddrs, addr)
	numLookupd := len(r.lookupdHTTPAddrs)
	r.mtx.Unlock()

	// if this is the first one, kick off the go loop
	if numLookupd == 1 {
		r.queryLookupd()
		r.wg.Add(1)
		go r.lookupdLoop()
	}

	return nil
}
// make an HTTP req to one of the configured nsqlookupd instances to discover
// which nsqd's provide the topic we are consuming.
//
// initiate a connection to any new producers that are identified.
func (r *Consumer) queryLookupd() {
	retries := 0

retry:
	endpoint := r.nextLookupdEndpoint()

	r.log(LogLevelInfo, "querying nsqlookupd %s", endpoint)

	var data lookupResp
	err := apiRequestNegotiateV1("GET", endpoint, nil, &data) // 从nsqlookupd中查找Producers
	if err != nil {
		r.log(LogLevelError, "error querying nsqlookupd (%s) - %s", endpoint, err)
		retries++
		if retries < 3 {
			r.log(LogLevelInfo, "retrying with next nsqlookupd")
			goto retry
		}
		return
	}

	var nsqdAddrs []string
	for _, producer := range data.Producers {
		broadcastAddress := producer.BroadcastAddress
		port := producer.TCPPort
		joined := net.JoinHostPort(broadcastAddress, strconv.Itoa(port))
		nsqdAddrs = append(nsqdAddrs, joined)
	}
	// apply filter
	if discoveryFilter, ok := r.behaviorDelegate.(DiscoveryFilter); ok {
		nsqdAddrs = discoveryFilter.Filter(nsqdAddrs)
	}
	for _, addr := range nsqdAddrs { // 跟每个producers建立连接
		err = r.ConnectToNSQD(addr)
		if err != nil && err != ErrAlreadyConnected {
			r.log(LogLevelError, "(%s) error connecting to nsqd - %s", addr, err)
			continue
		}
	}
}
```

```go
// ConnectToNSQD takes a nsqd address to connect directly to.
//
// It is recommended to use ConnectToNSQLookupd so that topics are discovered
// automatically.  This method is useful when you want to connect to a single, local,
// instance.
func (r *Consumer) ConnectToNSQD(addr string) error {
	if atomic.LoadInt32(&r.stopFlag) == 1 {
		return errors.New("consumer stopped")
	}

	if atomic.LoadInt32(&r.runningHandlers) == 0 {
		return errors.New("no handlers")
	}

	atomic.StoreInt32(&r.connectedFlag, 1)

	conn := NewConn(addr, &r.config, &consumerConnDelegate{r}) // 新建连接
	conn.SetLoggerLevel(r.getLogLevel())
	format := fmt.Sprintf("%3d [%s/%s] (%%s)", r.id, r.topic, r.channel)
	for index := range r.logger {
		conn.SetLoggerForLevel(r.logger[index], LogLevel(index), format)
	}
	r.mtx.Lock()
	_, pendingOk := r.pendingConnections[addr]
	_, ok := r.connections[addr]
	if ok || pendingOk {
		r.mtx.Unlock()
		return ErrAlreadyConnected
	}
	r.pendingConnections[addr] = conn
	if idx := indexOf(addr, r.nsqdTCPAddrs); idx == -1 {
		r.nsqdTCPAddrs = append(r.nsqdTCPAddrs, addr)
	}
	r.mtx.Unlock()

	r.log(LogLevelInfo, "(%s) connecting to nsqd", addr)

	cleanupConnection := func() {
		r.mtx.Lock()
		delete(r.pendingConnections, addr)
		r.mtx.Unlock()
		conn.Close()
	}

	resp, err := conn.Connect()
	if err != nil {
		cleanupConnection()
		return err
	}

	if resp != nil {
		if resp.MaxRdyCount < int64(r.getMaxInFlight()) {
			r.log(LogLevelWarning,
				"(%s) max RDY count %d < consumer max in flight %d, truncation possible",
				conn.String(), resp.MaxRdyCount, r.getMaxInFlight())
		}
	}

	cmd := Subscribe(r.topic, r.channel)
	err = conn.WriteCommand(cmd) // 启动订阅
	if err != nil {
		cleanupConnection()
		return fmt.Errorf("[%s] failed to subscribe to %s:%s - %s",
			conn, r.topic, r.channel, err.Error())
	}

	r.mtx.Lock()
	delete(r.pendingConnections, addr)
	r.connections[addr] = conn
	r.mtx.Unlock()

	// pre-emptive signal to existing connections to lower their RDY count
	for _, c := range r.conns() {
		r.maybeUpdateRDY(c)
	}

	return nil
}
func (r *Consumer) maybeUpdateRDY(conn *Conn) {
	inBackoff := r.inBackoff()
	inBackoffTimeout := r.inBackoffTimeout()
	if inBackoff || inBackoffTimeout {
		r.log(LogLevelDebug, "(%s) skip sending RDY inBackoff:%v || inBackoffTimeout:%v",
			conn, inBackoff, inBackoffTimeout)
		return
	}

	count := r.perConnMaxInFlight() // 将rdy平均分到每个nsqd连接
	r.log(LogLevelDebug, "(%s) sending RDY %d", conn, count)
	r.updateRDY(conn, count)
}
```

## Conn.Connect

```go
// Connect dials and bootstraps the nsqd connection
// (including IDENTIFY) and returns the IdentifyResponse
func (c *Conn) Connect() (*IdentifyResponse, error) {
	dialer := &net.Dialer{
		LocalAddr: c.config.LocalAddr,
		Timeout:   c.config.DialTimeout,
	}

	conn, err := dialer.Dial("tcp", c.addr)
	if err != nil {
		return nil, err
	}
	c.conn = conn.(*net.TCPConn)
	c.r = conn
	c.w = conn

	_, err = c.Write(MagicV2)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("[%s] failed to write magic - %s", c.addr, err)
	}

	resp, err := c.identify() // 发送client config，获取nsqd config
	if err != nil {
		return nil, err
	}

	if resp != nil && resp.AuthRequired {
		if c.config.AuthSecret == "" {
			c.log(LogLevelError, "Auth Required")
			return nil, errors.New("Auth Required")
		}
		err := c.auth(c.config.AuthSecret)
		if err != nil {
			c.log(LogLevelError, "Auth Failed %s", err)
			return nil, err
		}
	}

	c.wg.Add(2)
	atomic.StoreInt32(&c.readLoopRunning, 1)
	go c.readLoop() // 启动读循环
	go c.writeLoop()// 启动写循环
	return resp, nil
}
```
## Conn.readLoop
```go
func (c *Conn) readLoop() {
	delegate := &connMessageDelegate{c}
	for {
		if atomic.LoadInt32(&c.closeFlag) == 1 {
			goto exit
		}

		frameType, data, err := ReadUnpackedResponse(c)
		if err != nil {
			if err == io.EOF && atomic.LoadInt32(&c.closeFlag) == 1 {
				goto exit
			}
			if !strings.Contains(err.Error(), "use of closed network connection") {
				c.log(LogLevelError, "IO error - %s", err)
				c.delegate.OnIOError(c, err) // close conn
			}
			goto exit
		}

		if frameType == FrameTypeResponse && bytes.Equal(data, []byte("_heartbeat_")) {
			c.log(LogLevelDebug, "heartbeat received")
			c.delegate.OnHeartbeat(c) // do nothing
			err := c.WriteCommand(Nop())
			if err != nil {
				c.log(LogLevelError, "IO error - %s", err)
				c.delegate.OnIOError(c, err) // close conn
				goto exit
			}
			continue
		}

		switch frameType {
		case FrameTypeResponse:
			c.delegate.OnResponse(c, data) // if CLOSE_WAIT, close conn, otherwise do nothing
		case FrameTypeMessage:
			msg, err := DecodeMessage(data)
			if err != nil {
				c.log(LogLevelError, "IO error - %s", err)
				c.delegate.OnIOError(c, err) // close conn
				goto exit
			}
			msg.Delegate = delegate // connMessageDelegate
			msg.NSQDAddress = c.String()

			atomic.AddInt64(&c.messagesInFlight, 1)
			atomic.StoreInt64(&c.lastMsgTimestamp, time.Now().UnixNano())

			c.delegate.OnMessage(c, msg) // send to Consumer.incomingMessages
		case FrameTypeError:
			c.log(LogLevelError, "protocol error - %s", data)
			c.delegate.OnError(c, data) // do nothing
		default:
			c.log(LogLevelError, "IO error - %s", err)
			c.delegate.OnIOError(c, fmt.Errorf("unknown frame type %d", frameType)) // close conn
		}
	}

exit:
	atomic.StoreInt32(&c.readLoopRunning, 0)
	// start the connection close
	messagesInFlight := atomic.LoadInt64(&c.messagesInFlight)
	if messagesInFlight == 0 {
		// if we exited readLoop with no messages in flight
		// we need to explicitly trigger the close because
		// writeLoop won't
		c.close()
	} else {
		c.log(LogLevelWarning, "delaying close, %d outstanding messages", messagesInFlight)
	}
	c.wg.Done()
	c.log(LogLevelInfo, "readLoop exiting")
}
func (d *consumerConnDelegate) OnResponse(c *Conn, data []byte)       { d.r.onConnResponse(c, data) }
func (r *Consumer) onConnResponse(c *Conn, data []byte) {
	switch {
	case bytes.Equal(data, []byte("CLOSE_WAIT")):
		// server is ready for us to close (it ack'd our StartClose)
		// we can assume we will not receive any more messages over this channel
		// (but we can still write back responses)
		r.log(LogLevelInfo, "(%s) received CLOSE_WAIT from nsqd", c.String())
		c.Close()
	}
}

func (d *consumerConnDelegate) OnIOError(c *Conn, err error)          { d.r.onConnIOError(c, err) }
func (r *Consumer) onConnIOError(c *Conn, err error) {
	c.Close()
}

func (d *consumerConnDelegate) OnError(c *Conn, data []byte)          { d.r.onConnError(c, data) }
func (r *Consumer) onConnError(c *Conn, data []byte) {}

func (d *consumerConnDelegate) OnMessage(c *Conn, m *Message)         { d.r.onConnMessage(c, m) }
func (r *Consumer) onConnMessage(c *Conn, msg *Message) {
	atomic.AddUint64(&r.messagesReceived, 1)
	r.incomingMessages <- msg
}

func (d *consumerConnDelegate) OnHeartbeat(c *Conn)                   { d.r.onConnHeartbeat(c) }
func (r *Consumer) onConnHeartbeat(c *Conn) {}


```

## Conn.writeLoop
```go
func (c *Conn) writeLoop() {
	for {
		select {
		case <-c.exitChan:
			c.log(LogLevelInfo, "breaking out of writeLoop")
			// Indicate drainReady because we will not pull any more off msgResponseChan
			close(c.drainReady)
			goto exit
		case cmd := <-c.cmdChan: // Conn.onMessageTouch
			err := c.WriteCommand(cmd)
			if err != nil {
				c.log(LogLevelError, "error sending command %s - %s", cmd, err)
				c.close()
				continue
			}
		case resp := <-c.msgResponseChan: // Conn.onMessageRequeue(not success), Conn.onMessageFinish(success)
			// Decrement this here so it is correct even if we can't respond to nsqd
			msgsInFlight := atomic.AddInt64(&c.messagesInFlight, -1)

			if resp.success {
				c.log(LogLevelDebug, "FIN %s", resp.msg.ID)
				c.delegate.OnMessageFinished(c, resp.msg) // Consumer.messagesFinished++
				c.delegate.OnResume(c) // 	Consumer.startStopContinueBackoff(c, resumeFlag)
			} else {
				c.log(LogLevelDebug, "REQ %s", resp.msg.ID)
				c.delegate.OnMessageRequeued(c, resp.msg) // Consumer.messagesRequeued++
				if resp.backoff {
					c.delegate.OnBackoff(c) // 	Consumer.startStopContinueBackoff(c, backoffFlag)
				} else {
					c.delegate.OnContinue(c) // r.startStopContinueBackoff(c, continueFlag)
				}
			}

			err := c.WriteCommand(resp.cmd)
			if err != nil {
				c.log(LogLevelError, "error sending command %s - %s", resp.cmd, err)
				c.close()
				continue
			}

			if msgsInFlight == 0 &&
				atomic.LoadInt32(&c.closeFlag) == 1 {
				c.close()
				continue
			}
		}
	}

exit:
	c.wg.Done()
	c.log(LogLevelInfo, "writeLoop exiting")
}

func (d *consumerConnDelegate) OnMessageFinished(c *Conn, m *Message) { d.r.onConnMessageFinished(c, m) }
func (r *Consumer) onConnMessageFinished(c *Conn, msg *Message) {
	atomic.AddUint64(&r.messagesFinished, 1)
}

func (d *consumerConnDelegate) OnResume(c *Conn)                      { d.r.onConnResume(c) }
func (r *Consumer) onConnResume(c *Conn) {
	r.startStopContinueBackoff(c, resumeFlag)
}

func (d *consumerConnDelegate) OnMessageRequeued(c *Conn, m *Message) { d.r.onConnMessageRequeued(c, m) }
func (r *Consumer) onConnMessageRequeued(c *Conn, msg *Message) {
	atomic.AddUint64(&r.messagesRequeued, 1)
}

func (d *consumerConnDelegate) OnBackoff(c *Conn)                     { d.r.onConnBackoff(c) }
func (r *Consumer) onConnBackoff(c *Conn) {
	r.startStopContinueBackoff(c, backoffFlag)
}

func (d *consumerConnDelegate) OnContinue(c *Conn)                    { d.r.onConnContinue(c) }
func (r *Consumer) onConnContinue(c *Conn) {
	r.startStopContinueBackoff(c, continueFlag)
}

func (r *Consumer) startStopContinueBackoff(conn *Conn, signal backoffSignal) {
	// prevent many async failures/successes from immediately resulting in
	// max backoff/normal rate (by ensuring that we dont continually incr/decr
	// the counter during a backoff period)
	r.backoffMtx.Lock()
	defer r.backoffMtx.Unlock()
	if r.inBackoffTimeout() {
		return
	}

	// update backoff state
	backoffUpdated := false
	backoffCounter := atomic.LoadInt32(&r.backoffCounter)
	switch signal {
	case resumeFlag:
		if backoffCounter > 0 {
			backoffCounter--
			backoffUpdated = true
		}
	case backoffFlag:
		nextBackoff := r.config.BackoffStrategy.Calculate(int(backoffCounter) + 1)
		if nextBackoff <= r.config.MaxBackoffDuration {
			backoffCounter++
			backoffUpdated = true
		}
	}
	atomic.StoreInt32(&r.backoffCounter, backoffCounter)

	if r.backoffCounter == 0 && backoffUpdated {
		// exit backoff
		count := r.perConnMaxInFlight()
		r.log(LogLevelWarning, "exiting backoff, returning all to RDY %d", count)
		for _, c := range r.conns() {
			r.updateRDY(c, count)
		}
	} else if r.backoffCounter > 0 {
		// start or continue backoff
		backoffDuration := r.config.BackoffStrategy.Calculate(int(backoffCounter))

		if backoffDuration > r.config.MaxBackoffDuration {
			backoffDuration = r.config.MaxBackoffDuration
		}

		r.log(LogLevelWarning, "backing off for %s (backoff level %d), setting all to RDY 0",
			backoffDuration, backoffCounter)

		// send RDY 0 immediately (to *all* connections)
		for _, c := range r.conns() {
			r.updateRDY(c, 0)
		}

		r.backoff(backoffDuration)
	}
}

```
这里有一个backoff机制，每次Requeue都会触发backoff，backoffCounter++，如果backoffCounter>0则更新readyCount为0，不再接收新消息
backoff之后会有个定时器在backoffDuration之后调用resume恢复readyCount来接受消息，backoffDuration时间由config.BackoffStrategy计算
每次完成一条消息会将backoffCounter--，当backoffCounter更新为0时重新更新readyCount接收消息

这个机制应该是为了保护消费者，出现Requeue有可能是消息速率过高导致消费端处理不过来，产生了报错，所以应该等待一段时间再接收消息，让消息先堆积在nsqd上，如果有别的ready状态的消费者，则由那些消费组去处理

```go
func (r *Consumer) handlerLoop(handler Handler) {
	r.log(LogLevelDebug, "starting Handler")

	for {
		message, ok := <-r.incomingMessages
		if !ok {
			goto exit
		}

		if r.shouldFailMessage(message, handler) { // 消息重试次数超过config.MaxAttempts，直接Finish
			message.Finish() // 构建Finish命令发到c.msgResponseChan
			continue
		}

		err := handler.HandleMessage(message)
		if err != nil {
			r.log(LogLevelError, "Handler returned error (%s) for msg %s", err, message.ID)
			if !message.IsAutoResponseDisabled() { // 没关闭自动回复，出错时Requeue
				message.Requeue(-1) // 构建Requeue命令发到c.msgResponseChan
			}
			continue
		}

		if !message.IsAutoResponseDisabled() { // 没关闭自动回复，自动Finish
			message.Finish()
		}
	}

exit:
	r.log(LogLevelDebug, "stopping Handler")
	if atomic.AddInt32(&r.runningHandlers, -1) == 0 {
		r.exit()
	}
}
func (r *Consumer) shouldFailMessage(message *Message, handler interface{}) bool {
	// message passed the max number of attempts
	if r.config.MaxAttempts > 0 && message.Attempts > r.config.MaxAttempts {
		r.log(LogLevelWarning, "msg %s attempted %d times, giving up",
			message.ID, message.Attempts)

		logger, ok := handler.(FailedMessageLogger)
		if ok {
			logger.LogFailedMessage(message)
		}

		return true
	}
	return false
}

// Finish sends a FIN command to the nsqd which
// sent this message
func (m *Message) Finish() {
	if !atomic.CompareAndSwapInt32(&m.responded, 0, 1) {
		return
	}
	m.Delegate.OnFinish(m)
}

// Touch sends a TOUCH command to the nsqd which
// sent this message
func (m *Message) Touch() {
	if m.HasResponded() {
		return
	}
	m.Delegate.OnTouch(m)
}

// Requeue sends a REQ command to the nsqd which
// sent this message, using the supplied delay.
//
// A delay of -1 will automatically calculate
// based on the number of attempts and the
// configured default_requeue_delay
func (m *Message) Requeue(delay time.Duration) {
	m.doRequeue(delay, true)
}


type connMessageDelegate struct {
	c *Conn
}

func (d *connMessageDelegate) OnFinish(m *Message) { d.c.onMessageFinish(m) }
func (d *connMessageDelegate) OnRequeue(m *Message, t time.Duration, b bool) {
	d.c.onMessageRequeue(m, t, b)
}
func (d *connMessageDelegate) OnTouch(m *Message) { d.c.onMessageTouch(m) }
func (c *Conn) onMessageFinish(m *Message) {
	c.msgResponseChan <- &msgResponse{msg: m, cmd: Finish(m.ID), success: true}
}

func (c *Conn) onMessageRequeue(m *Message, delay time.Duration, backoff bool) {
	if delay == -1 {
		// linear delay
		delay = c.config.DefaultRequeueDelay * time.Duration(m.Attempts)
		// bound the requeueDelay to configured max
		if delay > c.config.MaxRequeueDelay {
			delay = c.config.MaxRequeueDelay
		}
	}
	c.msgResponseChan <- &msgResponse{msg: m, cmd: Requeue(m.ID, delay), success: false, backoff: backoff}
}

func (c *Conn) onMessageTouch(m *Message) {
	select {
	case c.cmdChan <- Touch(m.ID):
	case <-c.exitChan:
	}
}
```