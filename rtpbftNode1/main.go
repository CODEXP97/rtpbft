package main

import (
	"fmt"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"runtime"
	"strconv"
	"time"
)

const nodeCount = 70

var servers []server
var sigShares [][]byte
var threshold int
var suite *bn256.Suite

var timeStamp = time.Now()

var m string

//客户端的监听地址
var clientAddr = "127.0.0.1:8888"

//节点池，主要用来存储监听地址
var nodeTable map[string]string

func main() {

	genRsaKeys(nodeCount)

	m = "0"
	//为四个节点生成公私钥
	suite = bn256.NewSuite()
	f := 1
	threshold = 2*f + 1
	servers, sigShares = genRsaKeysTS(nodeCount, f, m, threshold, suite)

	//genRsaKeys(nodeCount)
	/*
		nodeTable = map[string]string{
			"N0": "127.0.0.1:9000",
			"N1": "127.0.0.1:9001",
			"N2": "127.0.0.1:9002",
			"N3": "127.0.0.1:9003",
		}*/
	nodeTable = make(map[string]string)
	for i := 0; i < nodeCount; i++ {
		var id = "N" + strconv.Itoa(i)
		//var id = strconv.Itoa(i)
		var addr string
		if i < 10 {
			addr = "127.0.0.1:900" + strconv.Itoa(i)
		} else {
			addr = "127.0.0.1:90" + strconv.Itoa(i)
		}

		nodeTable[id] = addr

	}
	fmt.Println(nodeTable)
	num := runtime.NumCPU()
	runtime.GOMAXPROCS(num - 1)
	for i := 0; i < nodeCount; i++ {
		var id = "N" + strconv.Itoa(i)
		//var id = strconv.Itoa(i)
		fmt.Println(id)
		p := NewPBFT(i, nodeTable[id])
		go p.tcpListen()

	}

	/*r := new(Request)
	r.Timestamp = time.Now().UnixNano()
	r.ClientAddr = clientAddr
	r.Message.ID = getRandom()
	//消息内容就是用户的输入
	r.Message.Content = strings.TrimSpace(m)
	br, err := json.Marshal(r)
	if err != nil {
		log.Panic(err)
	}

	fmt.Println(string(br))
	content := jointMessage(cRequest, br)
	//默认N0为主节点，直接把请求信息发送至N0
	tcpDial(content, nodeTable["N0"])*/

	/*

		p := NewPBFT("N0",nodeTable["N0"])
		go p.tcpListen()

		p1 := NewPBFT("N1",nodeTable["N1"])
		go p1.tcpListen()
		p2 := NewPBFT("N2",nodeTable["N2"])
		go p2.tcpListen()
		p3 := NewPBFT("N3",nodeTable["N3"])
		go p3.tcpListen()


		if len(os.Args) != 2 {
			log.Panic("输入的参数有误！")
		}

		nodeID := os.Args[1]
		if nodeID == "client" {
			clientSendMessageAndListen() //启动客户端程序
			//用户输入的节点在节点池列表中
		} else if addr, ok := nodeTable[nodeID]; ok {
			p := NewPBFT(nodeID, addr)
			go p.tcpListen() //启动节点
		} else {
			log.Fatal("无此节点编号！")
		}
		select {}


	*/
	select {}

}
