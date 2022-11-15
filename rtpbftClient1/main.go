package main

import (
	"strconv"
	"time"
)

const nodeCount = 70

var timeStamp = time.Now()
var Replycount = 0

//客户端的监听地址
var clientAddr = "127.0.0.1:8888"
var isStart = true

//节点池，主要用来存储监听地址
var nodeTable map[string]string

func main() {
	//为四个节点生成公私钥
	//genRsaKeys()

	nodeTable = make(map[string]string)
	for i := 0; i < nodeCount; i++ {
		var id = "N" + strconv.Itoa(i)
		var addr string
		if i < 10 {
			addr = "127.0.0.1:900" + strconv.Itoa(i)
			nodeTable[id] = addr
		} else {
			addr = "127.0.0.1:90" + strconv.Itoa(i)
			nodeTable[id] = addr
		}
	}
	/*	nodeTable = map[string]string{
			"N0": "127.0.0.1:9000",
			"N1": "127.0.0.1:9001",
			"N2": "127.0.0.1:9002",
			"N3": "127.0.0.1:9003",
		}
	*/
	clientSendMessageAndListen()

	/*
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
		select {}*/

}
