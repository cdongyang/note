# fix connection reset by peer

## error log
time="2020-05-26T17:30:49+08:00" level=debug msg=GotFirstResponseByte file=debug.go line=44
time="2020-05-26T17:30:54+08:00" level=info duration=2.447845ms ip=113.68.129.62 method=Work.QueuePackageApp nid=10404350 request="complete:true type:\"apk\" " service=ih5.editor uid=10000612
time="2020-05-26T17:30:54+08:00" level=info msg=200 duration=3m6.856511273s form="map[client:[10000612] domain:[file6793670914a4.dongyang.dev.h5sys.cn] eid:[10000586] gid:[10429] nid:[10404350] preview:[1] title:[tande] uid:[10000612] v41:[1]]" host=dongyang.dev.ivx.cn ip=113.68.129.62 method=POST nid=10404350 proto=https size=29858760 status=200 uid=10000612 uri="/work/packageApk/br5pp7m1bd3jqhe3ul90-9?v41=1&nid=10404350&uid=10000612&domain=file6793670914a4.dongyang.dev.h5sys.cn&title=tande&gid=10429&eid=10000586&client=10000612&preview=1"
2020/05/26 17:30:56 reverseproxy.go:437: httputil: ReverseProxy read error during body copy: read tcp 10.244.40.41:41582->10.244.40.41:42677: read: connection reset by peer
goroutine 1199 [running]:
runtime/debug.Stack(0xc000a1cd10, 0x4d7947, 0xc000088120)
	/usr/local/go/src/runtime/debug/stack.go:24 +0x9d
runtime/debug.PrintStack()
	/usr/local/go/src/runtime/debug/stack.go:16 +0x22
ih5.cn/util/logger.LogRequest.func1.1(0xc000970480, 0xc000f95200, 0xbfab5624f71e4cdb, 0x1b281ab25b, 0x2d6ca40, 0x0, 0x0, 0x0)
	/Users/vxplo/ivx/util/logger/http.go:86 +0xe2d
panic(0x18ecfa0, 0xc00003ad40)
	/usr/local/go/src/runtime/panic.go:679 +0x1b2
net/http/httputil.(*ReverseProxy).ServeHTTP(0xc001149d60, 0x1f77f80, 0xc000970480, 0xc000f95200)
	/usr/local/go/src/net/http/httputil/reverseproxy.go:299 +0x14c9
github.com/micro/go-micro/api/handler/web.(*webHandler).ServeHTTP(0xc0009704c0, 0x1f77f80, 0xc000970480, 0xc000f95200)
	/Users/vxplo/go/pkg/mod/github.com/micro/go-micro@v1.11.3/api/handler/web/web.go:51 +0x118
ih5.cn/gateway/gwhdr.(*metaHandler).ServeHTTP(0xc0005badc0, 0x1f77f80, 0xc000970480, 0xc000f95200)
	/Users/vxplo/ivx/gateway/gwhdr/meta.go:38 +0x6e1
ih5.cn/gateway/gwhdr.WithInternalHeader.func1(0x1f77f80, 0xc000970480, 0xc000f95200)
    /Users/vxplo/ivx/gateway/gwhdr/util.go:151 +0x14c
net/http.HandlerFunc.ServeHTTP(0xc0013b4860, 0x1f77f80, 0xc000970480, 0xc000f95200)
	/usr/local/go/src/net/http/server.go:2007 +0x44
net/http.HandlerFunc.ServeHTTP(...)
	/usr/local/go/src/net/http/server.go:2007
ih5.cn/util/logger.LogRequest.func1(0x7f23a8908148, 0xc001115c20, 0xc000f95200)
	/Users/vxplo/ivx/util/logger/http.go:141 +0x245
net/http.HandlerFunc.ServeHTTP(0xc000633760, 0x7f23a8908148, 0xc001115c20, 0xc000f95200)
	/usr/local/go/src/net/http/server.go:2007 +0x44
github.com/prometheus/client_golang/prometheus/promhttp.InstrumentHandlerInFlight.func1(0x7f23a8908148, 0xc001115c20, 0xc000f95200)
	/Users/vxplo/go/pkg/mod/github.com/prometheus/client_golang@v1.1.0/prometheus/promhttp/instrument_server.go:40 +0xbc
net/http.HandlerFunc.ServeHTTP(0xc000c2a870, 0x7f23a8908148, 0xc001115c20, 0xc000f95200)
	/usr/local/go/src/net/http/server.go:2007 +0x44
github.com/prometheus/client_golang/prometheus/promhttp.InstrumentHandlerCounter.func1(0x7f23a8908148, 0xc001115bd0, 0xc000f95200)
	/Users/vxplo/go/pkg/mod/github.com/prometheus/client_golang@v1.1.0/prometheus/promhttp/instrument_server.go:100 +0xda
net/http.HandlerFunc.ServeHTTP(0xc000c2a960, 0x7f23a8908148, 0xc001115bd0, 0xc000f95200)
	/usr/local/go/src/net/http/server.go:2007 +0x44
github.com/prometheus/client_golang/prometheus/promhttp.InstrumentHandlerDuration.func2(0x7f23a8908148, 0xc001115bd0, 0xc000f95200)
	/Users/vxplo/go/pkg/mod/github.com/prometheus/client_golang@v1.1.0/prometheus/promhttp/instrument_server.go:76 +0xb2
net/http.HandlerFunc.ServeHTTP(0xc000c2a9f0, 0x7f23a8908148, 0xc001115bd0, 0xc000f95200)
	/usr/local/go/src/net/http/server.go:2007 +0x44
github.com/prometheus/client_golang/prometheus/promhttp.InstrumentHandlerRequestSize.func2(0x7f23a8908148, 0xc001115bd0, 0xc000f95200)
	/Users/vxplo/go/pkg/mod/github.com/prometheus/client_golang@v1.1.0/prometheus/promhttp/instrument_server.go:170 +0x73
net/http.HandlerFunc.ServeHTTP(0xc000c2aa80, 0x7f23a8908148, 0xc001115bd0, 0xc000f95200)
	/usr/local/go/src/net/http/server.go:2007 +0x44
github.com/prometheus/client_golang/prometheus/promhttp.InstrumentHandlerResponseSize.func1(0x1f78e80, 0xc0000f8fc0, 0xc000f95200)
	/Users/vxplo/go/pkg/mod/github.com/prometheus/client_golang@v1.1.0/prometheus/promhttp/instrument_server.go:196 +0xe9
net/http.HandlerFunc.ServeHTTP(0xc000c2ab10, 0x1f78e80, 0xc0000f8fc0, 0xc000f95200)
	/usr/local/go/src/net/http/server.go:2007 +0x44
ih5.cn/gateway/gwhdr.(*srv).ServeHTTP(0xc000575200, 0x1f78e80, 0xc0000f8fc0, 0xc000f95100)
	/Users/vxplo/ivx/gateway/gwhdr/handler.go:159 +0x7b9
net/http.serverHandler.ServeHTTP(0xc0000f8700, 0x1f78e80, 0xc0000f8fc0, 0xc000f95100)
	/usr/local/go/src/net/http/server.go:2802 +0xa4
net/http.(*conn).serve(0xc000dfef00, 0x1f808c0, 0xc0009cd480)
	/usr/local/go/src/net/http/server.go:1890 +0x875
created by net/http.(*Server).Serve
	/usr/local/go/src/net/http/server.go:2928 +0x384
2020/05/26 17:30:56 server.go:3056: http: superfluous response.WriteHeader call from github.com/prometheus/client_golang/prometheus/promhttp.(*responseWriterDelegator).WriteHeader (delegator.go:58)
time="2020-05-26T17:30:56+08:00" level=error msg="net/http: abort Handler\n\n" duration=3m8.680993045s host=dongyang.dev.ivx.cn ip=113.68.129.62 method=POST nid=10404350 proto=https request="" size=28325212 status=500 uid=10000612 uri="/work/packageApk/br5pp7m1bd3jqhe3ul90-9?

	ln, err := (&net.ListenConfig{KeepAlive: 30 * time.Second}).Listen(opts.Context, "tcp", opts.Address)
	//ln, err := net.Listen("tcp", opts.Address)