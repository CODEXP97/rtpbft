package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"
)

//客户端使用的tcp监听
func clientTcpListen() {
	listen, err := net.Listen("tcp", clientAddr)
	if err != nil {
		log.Panic(err)
	}
	defer listen.Close()
	if isStart {
		isStart = false
		time.Sleep(time.Duration(100) * time.Microsecond)
	}

	for {

		conn, err := listen.Accept()

		if err != nil {
			log.Panic(err)
		}
		b, err := ioutil.ReadAll(conn)
		if err != nil {
			log.Panic(err)
		}
		Replycount++
		//fmt.Println(time.Since(timeStamp))
		if Replycount >= (nodeCount / 3 * 2) {
			fmt.Println(time.Since(timeStamp))
		} else {
			fmt.Println(string(b))
		}

	}

}

//节点使用的tcp监听
func (p *pbft) tcpListen() {
	listen, err := net.Listen("tcp", p.node.addr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("节点开启监听，地址：%s\n", p.node.addr)
	defer listen.Close()

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Panic(err)
		}
		b, err := ioutil.ReadAll(conn)
		if err != nil {
			log.Panic(err)
		}
		p.handleRequest(b)
	}

}

//使用tcp发送消息
func tcpDial(context []byte, addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Println("connect error", err)
		return
	}

	_, err = conn.Write(context)
	if err != nil {
		log.Fatal(err)
	}
	conn.Close()
}
