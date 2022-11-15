package main

/*
type server struct {
	privateKey *share.PriShare
	publicKey  *share.PubPoly
	message    []byte
}
*/
/*
func makeServer(n int, f int, threshold int, suite *bn256.Suite) ([]server, [][]byte) {
	m := "hello"

	servers := make([]server, n)

	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)

	for i, x := range priPoly.Shares(n) {

		servers[i].privateKey = x      //将私钥赋予节点i
		servers[i].publicKey = pubPoly //将公钥赋予节点i
		servers[i].message = []byte(m)
		sig, _ := tbls.Sign(suite, servers[i].privateKey, servers[i].message) //生成部分签名
		if i == f {
			sig[0] ^= 0x10
		} else {
			sigShares = append(sigShares, sig) //生成数字签名
		}
	}
	return servers, sigShares
}
*/
/*
func threshldVerify(servers []server, n, threshold int, suite *bn256.Suite, sigShares [][]byte) []string {
	results := make([]string, n)
	for i := 0; i < n; i++ {
		sig, _ := tbls.Recover(suite, servers[i].publicKey, servers[i].message, sigShares, threshold, n)
		err := bls.Verify(suite, servers[i].publicKey.Commit(), servers[i].message, sig) //用公钥验证数字签名
		if err == nil {
			results[i] = "Success"
		} else {
			results[i] = "Fault"
		}
	}
	return results
}
*/
