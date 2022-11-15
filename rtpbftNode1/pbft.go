package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"io/ioutil"
	"log"
	"strconv"
	"sync"
	"time"
)

//本地消息池（模拟持久化层），只有确认提交成功后才会存入此池
var localMessagePool = []Message{}

type node struct {
	//节点ID
	nodeID int
	//节点监听地址
	addr string
	//RSA私钥
	rsaPrivKey []byte
	//RSA公钥
	rsaPubKey []byte
	//TS私钥
	tsPrivKey *share.PriShare
	//TS公钥
	tsPubKey *share.PubPoly
}

type pbft struct {
	//节点信息
	node node
	//每笔请求自增序号
	sequenceID int
	//锁
	lock sync.Mutex
	//临时消息池，消息摘要对应消息本体
	messagePool map[string]Request
	//存放收到的prepare数量(至少需要收到并确认2f个)，根据摘要来对应
	prePareConfirmCount map[string]map[string]bool
	//存放收到的commit数量（至少需要收到并确认2f+1个），根据摘要来对应
	commitConfirmCount map[string]map[string]bool
	//该笔消息是否已进行Commit广播
	isCommitBordcast map[string]bool
	//该笔消息是否已对客户端进行Reply
	isReply map[string]bool
}

func NewPBFT(nodeID int, addr string) *pbft {
	p := new(pbft)
	p.node.nodeID = nodeID
	p.node.addr = addr
	p.node.rsaPrivKey = p.getPivKey("N" + strconv.Itoa(nodeID)) //从生成的私钥文件处读取
	p.node.rsaPubKey = p.getPubKey("N" + strconv.Itoa(nodeID))  //从生成的私钥文件处读取
	p.node.tsPrivKey = servers[nodeID].privateKey               //从生成的私钥文件处读取
	p.node.tsPubKey = servers[nodeID].publicKey                 //从生成的私钥文件处读取
	p.sequenceID = 0
	p.messagePool = make(map[string]Request)
	p.prePareConfirmCount = make(map[string]map[string]bool)
	p.commitConfirmCount = make(map[string]map[string]bool)
	p.isCommitBordcast = make(map[string]bool)
	p.isReply = make(map[string]bool)
	return p
}

func (p *pbft) handleRequest(data []byte) {
	//切割消息，根据消息命令调用不同的功能
	cmd, content := splitMessage(data)
	switch command(cmd) {
	case cRequest:
		p.handleClientRequest(content)
	case cPrePrepare:
		p.handlePrePrepare(content)
	case cPrepare:
		p.handlePrepare(content)
	case cCommit:
		p.handleCommit(content)
	}
}

//处理客户端发来的请求 主节点收到请求，把交易打包给各个节点
func (p *pbft) handleClientRequest(content []byte) {
	fmt.Printf("主节点N%s已接收到客户端发来的request ...", strconv.Itoa(p.node.nodeID))
	//使用json解析出Request结构体
	r := new(Request)
	err := json.Unmarshal(content, r)
	if err != nil {
		log.Panic(err)
	}
	//添加信息序号
	p.sequenceIDAdd()
	//获取消息摘要
	digest := getDigest(*r)
	fmt.Println("已将request存入临时消息池")
	//存入临时消息池
	p.messagePool[digest] = *r
	//主节点对消息摘要进行签名
	digestByte, _ := hex.DecodeString(digest)
	signInfo := p.RsaSignWithSha256(digestByte, p.node.rsaPrivKey)
	//拼接成PrePrepare，准备发往follower节点
	pp := PrePrepare{*r, digest, p.sequenceID, signInfo}
	b, err := json.Marshal(pp)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("正在向其他节点进行进行PrePrepare广播 ...")
	//进行PrePrepare广播
	p.broadcast(cPrePrepare, b)
	fmt.Println("PrePrepare广播完成")
}

//处理预准备消息 节点验证主节点，并把签名后的信息发送给主节点
func (p *pbft) handlePrePrepare(content []byte) {
	fmt.Printf("本节点N%s已接收到主节点发来的PrePrepare ...", strconv.Itoa(p.node.nodeID))
	//使用json解析出PrePrepare结构体
	pp := new(PrePrepare)
	err := json.Unmarshal(content, pp)
	if err != nil {
		log.Panic(err)
	}
	//获取主节点的公钥，用于数字签名验证
	primaryNodePubKey := p.getPubKey("N0")
	digestByte, _ := hex.DecodeString(pp.Digest)
	if digest := getDigest(pp.RequestMessage); digest != pp.Digest {
		fmt.Println("信息摘要对不上，拒绝进行prepare广播")
	} else if p.sequenceID+1 != pp.SequenceID {
		fmt.Println("消息序号对不上，拒绝进行prepare广播")
	} else if !p.RsaVerySignWithSha256(digestByte, pp.Sign, primaryNodePubKey) {
		fmt.Println("主节点签名验证失败！,拒绝进行prepare广播")
	} else {
		//序号赋值
		p.sequenceID = pp.SequenceID
		//将信息存入临时消息池
		fmt.Println("已将消息存入临时节点池") //消息池单独创建
		p.messagePool[pp.Digest] = pp.RequestMessage
		//节点使用私钥对其签名
		sign, _ := tbls.Sign(suite, servers[p.node.nodeID].privateKey, []byte(m))
		//拼接成Prepare
		pre := Prepare{pp.Digest, pp.SequenceID, p.node.nodeID, sign}
		bPre, err := json.Marshal(pre)
		if err != nil {
			log.Panic(err)
		}
		//进行准备阶段的广播
		fmt.Println("正在进行Prepare广播 ...")
		message := jointMessage(cPrepare, bPre)
		go tcpDial(message, nodeTable["N0"])
		//p.broadcastN(cPrepare, bPre)
		fmt.Println("Prepare广播完成")
	}
}

//处理准备消息 主节点监听收到信息，并验证，再次进行广播
func (p *pbft) handlePrepare(content []byte) {
	//使用json解析出Prepare结构体
	pre := new(Prepare)
	err := json.Unmarshal(content, pre)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("本节点N%s已接收到N%s节点发来的Prepare ... \n", strconv.Itoa(p.node.nodeID), strconv.Itoa(pre.NodeID))
	//获取消息源节点的公钥，用于数字签名验证
	//MessageNodePubKey := p.getPubKey(strconv.Itoa(pre.NodeID))
	digestByte, _ := hex.DecodeString(pre.Digest)

	if pre.NodeID == 2 {
		if !threshldVerify(m, servers, nodeCount, threshold, suite, sigShares) {
			fmt.Println("节点签名验证失败！,拒绝执行commit广播")
		}
	}

	/*else if !threshldVerify(m, servers, nodeCount, threshold, suite, sigShares) {
		fmt.Println("节点签名验证失败！,拒绝执行commit广播")
	} */
	if _, ok := p.messagePool[pre.Digest]; !ok {
		fmt.Println("当前临时消息池无此摘要，拒绝执行commit广播")
	} else if p.sequenceID != pre.SequenceID {
		fmt.Println("消息序号对不上，拒绝执行commit广播")
	} else {
		p.setPrePareConfirmMap(pre.Digest, strconv.Itoa(pre.NodeID), true)
		count := 0
		for range p.prePareConfirmCount[pre.Digest] {
			count++
		}
		//因为主节点不会发送Prepare，所以不包含自己
		specifiedCount := 0
		if p.node.nodeID == 0 {
			specifiedCount = nodeCount / 3 * 2
		} else {
			specifiedCount = (nodeCount / 3 * 2) - 1
		}

		//如果节点至少收到了2f个prepare的消息（包括自己）,并且没有进行过commit广播，则进行commit广播
		p.lock.Lock()
		//获取消息源节点的公钥，用于数字签名验证
		if count >= specifiedCount && !p.isCommitBordcast[pre.Digest] {
			fmt.Printf("节点N%s已收到至少2f个节点(包括本地节点)发来的Prepare信息 ...\n", strconv.Itoa(p.node.nodeID))
			//节点使用私钥对其签名
			sign := p.RsaSignWithSha256(digestByte, p.node.rsaPrivKey)
			c := Commit{pre.Digest, pre.SequenceID, strconv.Itoa(p.node.nodeID), sign}
			bc, err := json.Marshal(c)
			if err != nil {
				log.Panic(err)
			}
			//进行提交信息的广播
			fmt.Printf("结点N%s正在进行commit广播 \n", strconv.Itoa(p.node.nodeID))
			p.broadcast(cCommit, bc)
			p.isCommitBordcast[pre.Digest] = true
			fmt.Printf("结点N%scommit广播完成\n", strconv.Itoa(p.node.nodeID))
		}
		p.lock.Unlock()
	}
}

//处理提交确认消息	各节点收到信息，验证，再传给主节点
func (p *pbft) handleCommit(content []byte) {
	//使用json解析出Commit结构体
	c := new(Commit)
	err := json.Unmarshal(content, c)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("本节点N%s已接收到N%s节点发来的Commit ... \n", strconv.Itoa(p.node.nodeID), c.NodeID)
	//获取消息源节点的公钥，用于数字签名验证
	MessageNodePubKey := p.getPubKey("N" + c.NodeID)
	digestByte, _ := hex.DecodeString(c.Digest)
	/*if _, ok := p.prePareConfirmCount[c.Digest]; !ok {
		fmt.Println("当前prepare池无此摘要，拒绝将信息持久化到本地消息池")
	} else*/if p.sequenceID != c.SequenceID {
		fmt.Println("消息序号对不上，拒绝将信息持久化到本地消息池")
	} else if !p.RsaVerySignWithSha256(digestByte, c.Sign, MessageNodePubKey) {
		fmt.Println("节点签名验证失败！,拒绝将信息持久化到本地消息池")
	} else {
		p.setCommitConfirmMap(c.Digest, c.NodeID, true)
		count := 0
		for range p.commitConfirmCount[c.Digest] {
			count++
		}
		//如果节点至少收到了2f+1个commit消息（包括自己）,并且节点没有回复过,并且已进行过commit广播，则提交信息至本地消息池，并reply成功标志至客户端！
		p.lock.Lock()
		//if count >= nodeCount/3*2 && !p.isReply[c.Digest] && p.isCommitBordcast[c.Digest]
		if count >= 1 {
			fmt.Printf("本节点%s已收到至少2f + 1 个节点(包括本地节点)发来的Commit信息 ...", strconv.Itoa(p.node.nodeID))
			//将消息信息，提交到本地消息池中！
			localMessagePool = append(localMessagePool, p.messagePool[c.Digest].Message)
			info := strconv.Itoa(p.node.nodeID) + "节点已将msgid:" + strconv.Itoa(p.messagePool[c.Digest].ID) + "存入本地消息池中,消息内容为：" + p.messagePool[c.Digest].Content
			fmt.Println(info)
			fmt.Printf("节点%s正在reply客户端 ...\n", strconv.Itoa(p.node.nodeID))
			go tcpDial([]byte(info), p.messagePool[c.Digest].ClientAddr)
			//go tcpDial([]byte(info), nodeTable["N0"])
			p.isReply[c.Digest] = true
			fmt.Printf("节点%sreply完毕\n", strconv.Itoa(p.node.nodeID))

			fmt.Println(time.Since(timeStamp))
			//p.messagePool = make(map[string]Request)
			//p.prePareConfirmCount = make(map[string]map[string]bool)
			//p.commitConfirmCount = make(map[string]map[string]bool)
			//p.isCommitBordcast = make(map[string]bool)

		}

		p.lock.Unlock()
	}
}

//序号累加
func (p *pbft) sequenceIDAdd() {
	p.lock.Lock()
	p.sequenceID++
	p.lock.Unlock()
}

//向除自己外的其他节点进行广播
func (p *pbft) broadcast(cmd command, content []byte) {
	for i := range nodeTable {
		if i == "N"+strconv.Itoa(p.node.nodeID) {
			continue
		}
		message := jointMessage(cmd, content)
		go tcpDial(message, nodeTable[i])
	}
}

func (p *pbft) broadcastN(cmd command, content []byte) {
	message := jointMessage(cmd, content)
	go tcpDial(message, nodeTable["N0"])
}

//为多重映射开辟赋值
func (p *pbft) setPrePareConfirmMap(val, val2 string, b bool) {
	if _, ok := p.prePareConfirmCount[val]; !ok {
		p.prePareConfirmCount[val] = make(map[string]bool)
	}
	p.prePareConfirmCount[val][val2] = b
}

//为多重映射开辟赋值
func (p *pbft) setCommitConfirmMap(val, val2 string, b bool) {
	if _, ok := p.commitConfirmCount[val]; !ok {
		p.commitConfirmCount[val] = make(map[string]bool)
	}
	p.commitConfirmCount[val][val2] = b
}

//传入节点编号， 获取对应的公钥
func (p *pbft) getPubKey(nodeID string) []byte {
	key, err := ioutil.ReadFile("Keys/" + nodeID + "/" + nodeID + "_RSA_PUB")
	if err != nil {
		log.Panic(err)
	}
	return key
}

//传入节点编号， 获取对应的私钥
func (p *pbft) getPivKey(nodeID string) []byte {
	key, err := ioutil.ReadFile("Keys/" + nodeID + "/" + nodeID + "_RSA_PIV")
	if err != nil {
		log.Panic(err)
	}
	return key
}
