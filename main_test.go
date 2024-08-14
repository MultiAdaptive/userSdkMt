package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"io/ioutil"
	"log"
	"math/big"
	"testing"
	"usersdk/contract"
)

func TestPrivateKeyToAddress(t *testing.T) {
	keystoreFile := "/Users/wuxinyang/Desktop/test/UTC--2024-07-25T06-42-31.156489832Z--a69bc320eee06da583f0c762e94bd7c2f13f0219"
	// keystore文件密码
	password := "123456"

	// 读取keystore文件
	keyJson, err := ioutil.ReadFile(keystoreFile)
	if err != nil {
		log.Fatal(err)
	}

	// 解锁keystore文件以获取私钥
	key, err := keystore.DecryptKey(keyJson, password)
	if err != nil {
		log.Fatal(err)
	}

	// 获取私钥
	privateKey := key.PrivateKey
	fmt.Printf("私钥: %x\n", privateKey.D.Bytes())

	// 获取地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("地址: %s\n", address.Hex())

}

func TestNewUserService(t *testing.T) {
	client,err:= ethclient.Dial(Url)
	if err !=nil {
		println("err-----",err.Error())
	}

	addr := common.HexToAddress(NodeContractAddress)
	instance, err := contract.NewNodeManager(addr, client)
	if err != nil {
		//http.Error(w, "No Node Info found", http.StatusNotFound)
		return
	}
	nodes, err := instance.GetBroadcastingNodes(nil)
	//log.Info("GetBroadcastingNodes-----", "nodes", len(nodes))
	//num,err :=  client.BlockNumber(context.Background())
	//if err != nil {
	//	println("err-----",err)
	//}

	for _,node := range nodes{
		println("node----",node.Addr.Hex())
	}

}

func TestNewUserService2(t *testing.T) {
	client,err:= ethclient.Dial(Url)
	if err !=nil {
		println("err-----",err.Error())
	}
	num,_ := client.BlockNumber(context.Background())
	println("num---",num)
}

func TestGenerateCommitProofAndPointWithData(t *testing.T) {
	client,err:= ethclient.Dial(Url)
	if err !=nil {
		println("err-----",err.Error())
	}
	block,err := client.BlockByNumber(context.Background(),new(big.Int).SetUint64(6396134))
	if err != nil {
		println("block num err----",err.Error())
	}
	for _,tx := range block.Transactions(){
		if tx.To() != nil {
			switch tx.To().String() {
			case "0xa8ED91Eb2B65A681A742011798d7FB31C50FA724":
				txData := tx.Data()
				dataStr := common.Bytes2Hex(txData)
				value := txData[4: 4+32]
				last8Bytes := value[len(value)-8:]
				varStr := common.Bytes2Hex(value)
				i := binary.BigEndian.Uint64(last8Bytes)
				println("dataStr----",dataStr)
				println("varStr-----",varStr,"i-----",i)
			}
		}
	}
}