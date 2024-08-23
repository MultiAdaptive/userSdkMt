package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/exp/rand"
	"io/ioutil"
	"log"
	"math/big"
	"testing"
	"time"
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
	client,err:= ethclient.Dial(SignUrl)
	if err !=nil {
		println("err-----",err.Error())
	}
	private,addr := PrivateKeyToAddress(privateKey)
	println("---addr",addr.Hex())
	l1Client,err := ethclient.Dial(Url)
	if err != nil {
		println("err---1--",err.Error())
	}
	instance, err := contract.NewCommitmentManager(common.HexToAddress(CommitmentContractAddress), l1Client)
	index, err := instance.Indices(nil, addr)
	data := make([]byte, 1024*1024)
	_, err = rand.Read(data)
	das := common.HexToHash(nodeGroupKeyStr)
	commit,proof,point := GenerateCommitProofAndPointWithData(data)
	outData := time.Now()
	tm := time.Date(outData.Year(), outData.Month(), outData.Day(), outData.Hour(), 0, 0, 0, outData.Location())
	outTimeStamp := tm.Add(24*time.Hour).Unix()
	println("请求签名-------")
	sign1,err := signature(client,addr,index.Uint64(),1024*1024,commit,data,das,proof,point,uint64(outTimeStamp))
	if err != nil {
		println("----err",err.Error())
		return
	}
	signStr1 := common.Bytes2Hex(sign1)
	println("signStr1-----",signStr1)

	auth, err := bind.NewKeyedTransactorWithChainID(private, big.NewInt(ChainID)) // For Mainnet
	if err != nil {
		println("err",err.Error())
	}
	// dasKey  签名所在组织的hash key

	var digest kzg.Digest
	digest.SetBytes(commit)
	commitData := contract.PairingG1Point{
		X: new(big.Int).SetBytes(digest.X.Marshal()),
		Y: new(big.Int).SetBytes(digest.Y.Marshal()),
	}
	signs := [][]byte{sign1}
	daskey := common.HexToHash("0x8af361a6d746c89b15a8bce2f9be881e6638b4b17ab7375a89ead3474e341687")
	tx, err := instance.SubmitCommitment(auth, new(big.Int).SetUint64(1024*1024), new(big.Int).SetInt64(outTimeStamp), common.Hash{} ,daskey, signs, commitData)
	// 等待交易被打包并获取交易哈希
	fmt.Println("交易哈希:", tx.Hash().Hex())
	// 等待交易被确认
	receipt, err := bind.WaitMined(context.Background(), client, tx)
	if err != nil {
		errStr := fmt.Sprintf("cant WaitMined by contract address err:%s", err.Error())
		log.Fatal(errStr)
	}
	// 检查交易状态SignData
	if receipt.Status == types.ReceiptStatusFailed {
		log.Fatal("交易失败")
	}
	fmt.Println("交易成功!")
}

func signature(client *ethclient.Client,sender common.Address, index, length uint64, commitment, data []byte, nodeGroupKey [32]byte, proof, claimedValue []byte, timeout uint64) ([]byte, error) {
	// Connect to the Ethereum client at the specified URL
	ctx := context.Background()
	var result []byte
	// Call the eth_sendDAByParams method to get the signature
	err := client.Client().CallContext(ctx, &result, "mta_sendDAByParams", sender, index, length, commitment, data, nodeGroupKey, proof, claimedValue, timeout,[]byte{})
	return result, err
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