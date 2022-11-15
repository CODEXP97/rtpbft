package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"log"
	"os"
	"strconv"
)

type server struct {
	privateKey *share.PriShare
	publicKey  *share.PubPoly
	message    []byte
}

//门限签名
func genRsaKeysTS(nodeNum int, f int, m string, threshold int, suite *bn256.Suite) ([]server, [][]byte) {
	servers1 := make([]server, nodeNum)

	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares1 := make([][]byte, 0)

	for i, x := range priPoly.Shares(nodeNum) {

		servers1[i].privateKey = x      //将私钥赋予节点i
		servers1[i].publicKey = pubPoly //将公钥赋予节点i
		servers1[i].message = []byte(m)

		sig, _ := tbls.Sign(suite, servers1[i].privateKey, servers1[i].message) //生成部分签名
		if i == f {
			sig[0] ^= 0x10
		} else {
			sigShares1 = append(sigShares1, sig) //生成数字签名
		}
	}

	fmt.Println("已为节点们生成TS公私钥")
	return servers1, sigShares1
}

//门限签名验证
func threshldVerify(m string, servers []server, n, threshold int, suite *bn256.Suite, sigShares [][]byte) bool {
	results := make([]string, n)
	for i := 0; i < n; i++ {
		sig, _ := tbls.Recover(suite, servers[i].publicKey, []byte(m), sigShares, threshold, n)
		err := bls.Verify(suite, servers[i].publicKey.Commit(), []byte(m), sig) //用公钥验证数字签名
		if err == nil {
			results[i] = "Success"
		} else {
			results[i] = "Fault"
			return false
		}
	}
	return true
}

//如果当前目录下不存在目录Keys，则创建目录，并为各个节点生成rsa公私钥
func genRsaKeys(nodeNum int) {
	if !isExist("./Keys") {
		fmt.Println("检测到还未生成公私钥目录，正在生成公私钥 ...")
		err := os.Mkdir("Keys", 0644)
		if err != nil {
			log.Panic()
		}
		for i := 0; i <= nodeNum; i++ {
			if !isExist("./Keys/N" + strconv.Itoa(i)) {
				err := os.Mkdir("./Keys/N"+strconv.Itoa(i), 0644)
				if err != nil {
					log.Panic()
				}
			}
			priv, pub := getKeyPair()
			privFileName := "Keys/N" + strconv.Itoa(i) + "/N" + strconv.Itoa(i) + "_RSA_PIV"
			file, err := os.OpenFile(privFileName, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				log.Panic(err)
			}
			defer file.Close()
			file.Write(priv)

			pubFileName := "Keys/N" + strconv.Itoa(i) + "/N" + strconv.Itoa(i) + "_RSA_PUB"
			file2, err := os.OpenFile(pubFileName, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				log.Panic(err)
			}
			defer file2.Close()
			file2.Write(pub)
		}
		fmt.Println("已为节点们生成RSA公私钥")
	}
}

//生成rsa公私钥
func getKeyPair() (prvkey, pubkey []byte) {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)
	return
}

//判断文件或文件夹是否存在
func isExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		if os.IsNotExist(err) {
			return false
		}
		fmt.Println(err)
		return false
	}
	return true
}

//数字签名
func (p *pbft) RsaSignWithSha256(data []byte, keyBytes []byte) []byte {
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("private key error"))
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey err", err)
		panic(err)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		panic(err)
	}

	return signature
}

//签名验证
func (p *pbft) RsaVerySignWithSha256(data, signData, keyBytes []byte) bool {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("public key error"))
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signData)
	if err != nil {
		panic(err)
	}
	return true
}
