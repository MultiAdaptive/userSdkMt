package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"usersdk/contract"

	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	kzgSdk "github.com/multiAdaptive/kzg-sdk"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	//"usersdk/contract"
)

var(
	Url                       string = "https://eth-sepolia.g.alchemy.com/v2/dalC8j26yBwo67xTPdbWfPAnbATV5Jqy"
	TokenContractAddress      string = "0x3e0F3B6235fC7f8F0Dd5d74e026f7e08c07D0557"
	StorageManagementAddress  string = "0x44214b40b88BeD3424b2684bE6b102fD3BCA4a09"
	ApproveValue              uint64 = 1000000000000000
	CommitmentContractAddress string = "0xb945872cbF327DA5CBEb6aE7286ccEE6CAaBA3B2"
	NodeContractAddress       string = "0xed592c8F0B13bb8A761BFFb6140720D89552999B"
	ChainID                   int64  = 11155111
	//nodeGroupSingle             string = "0x8af361a6d746c89b15a8bce2f9be881e6638b4b17ab7375a89ead3474e341687"
	nodeGroupKeyStr string = "0x8af361a6d746c89b15a8bce2f9be881e6638b4b17ab7375a89ead3474e341687"
	RegistNodeAddr            string = ""
	BroadCastKeyStorePth      string = "./keystoreFile"
	StorageKeyStorePth        string = "./keystoreFileS"
	PWD                       string = "123456"
	SignUrl                   string = "https://test.eth.b01.multiadaptive.com"
	//SignUrl                   string = "http://54.151.240.239:8545"
	SignUrl2                  string = "http://54.80.136.172:8545"
	privateKey                string = "3180b6cc1ef8d68c00dc30c83b9f00321a60dbeeac202e7671312dc0cd9707b9"
)
const (
	Key1 = "signStr1-"
	Key2 = "signStr2-"
	Key3 = "commit-"
	Key4 = "time-"
)

type UserService struct {
	ctx       context.Context
	client1    *ethclient.Client
	client2    *ethclient.Client
	priv      *ecdsa.PrivateKey
	addr      common.Address
	privStr    string
	localFile *os.File
}

func NewUserService(priv string) *UserService {
	client1, err := ethclient.Dial(SignUrl)
	if err != nil {
		println("client1-----err",err.Error())
	}
	client2, err := ethclient.Dial(SignUrl2)
	if err != nil {
		println("client2-----err",err.Error())
	}
	private, add := PrivateKeyToAddress(priv)
	filePath := "./signInfo.txt"

	// 打开文件，如果文件不存在则创建
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		fmt.Println("Error opening or creating file:", err)
	}
	return &UserService{
		ctx:       context.Background(),
		client1:   client1,
		client2:   client2,
		priv:      private,
		addr:       add,
		privStr:   priv,
		localFile: file,
	}
}

func (u *UserService) GetIndex() int {
	client, err := ethclient.Dial(Url)
	if err != nil {
		return 0
	}
	instance, err := contract.NewCommitmentManager(common.HexToAddress(CommitmentContractAddress), client)
	if err != nil {
		return 0
	}
	index, err := instance.Indices(nil, u.addr)
	if err != nil {
		return 0
	}
	return int(index.Int64())
}

func (u *UserService) SendDataToExecClient1k() {
	defer u.localFile.Close()
	nonce := u.GetIndex()
	println("查询到的当前index nonce为",nonce)
	total := 1024
	for index := nonce;index<total;index++ {
		index := index
		println("当前-----index",index)
		data := make([]byte, 1024*1024)
		_, err := rand.Read(data)
		das := common.HexToHash(nodeGroupKeyStr)
		if u.priv == nil || len(u.addr.Bytes()) == 0 {
			priv,addr := PrivateKeyToAddress(u.privStr)
			u.priv = priv
			u.addr = addr
		}
		commit,proof,point := GenerateCommitProofAndPointWithData(data)
		outData := time.Now()
		tm := time.Date(outData.Year(), outData.Month(), outData.Day(), outData.Hour(), 0, 0, 0, outData.Location())
		outTimeStamp := tm.Add(24*time.Hour).Unix()
		// 创建一个上下文，用于取消交易
		sign1,err := u.signature(u.addr,uint64(index),1024*1024,commit,data,das,proof,point,uint64(outTimeStamp))
		signStr1 := common.Bytes2Hex(sign1)
		println("signStr1-----",signStr1)

		var sign2 []byte
		sign2,err = u.signature2(u.addr,uint64(index),1024*1024,commit,data,das,proof,point,uint64(outTimeStamp))
		if err != nil {
			fmt.Printf("mta_sendDAByParams----send----signUrl:%s ,err:%@",SignUrl2,err)
		}
		signStr2 := common.Bytes2Hex(sign2)
		println("signStr2-----",signStr2)
		nonce++

		key1 := Key1
		key2 := Key2
		key3 := Key3
		key4 := Key4
		indexStr := strconv.Itoa(index)
		key1 += indexStr
		key2 += indexStr
		key3 += indexStr
		key4 += indexStr
		// 以追加的方式写入文件
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key1, signStr1)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key2, signStr2)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		cmStr := common.Bytes2Hex(commit)
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key3, cmStr)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}

		timeStr := strconv.Itoa(int(outTimeStamp))
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key4, timeStr)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}
	countStr := strconv.Itoa(total)
	fmt.Fprintf(u.localFile, "%s:%s\n", "count", countStr)
}

func (u *UserService)signature(sender common.Address, index, length uint64, commitment, data []byte, nodeGroupKey [32]byte, proof, claimedValue []byte, timeout uint64) ([]byte, error) {
	// Connect to the Ethereum client at the specified URL
	ctx := context.Background()
	var result []byte
	// Call the eth_sendDAByParams method to get the signature
	err := u.client1.Client().CallContext(ctx, &result, "mta_sendDAByParams", sender, index, length, commitment, data, nodeGroupKey, proof, claimedValue, timeout,[]byte{})
	return result, err
}

func (u *UserService)signature2(sender common.Address, index, length uint64, commitment, data []byte, nodeGroupKey [32]byte, proof, claimedValue []byte, timeout uint64) ([]byte, error) {
	// Connect to the Ethereum client at the specified URL
	ctx := context.Background()
	var result []byte
	// Call the eth_sendDAByParams method to get the signature
	err := u.client2.Client().CallContext(ctx, &result, "mta_sendDAByParams", sender, index, length, commitment, data, nodeGroupKey, proof, claimedValue, timeout,[]byte{})
	return result, err
}

func (u *UserService) SendDataToExecClient3k() {
	defer u.localFile.Close()
	total := 1024 / 3 + 1
	nonce := u.GetIndex()
	for index := 0;index<total;index++ {
		index := index
		println("当前-----index",index)
		data := make([]byte, 1024*1024*3)
		_, err := rand.Read(data)
		das := common.HexToHash(nodeGroupKeyStr)
		if u.priv == nil || len(u.addr.Bytes()) == 0 {
			priv,addr := PrivateKeyToAddress(u.privStr)
			u.priv = priv
			u.addr = addr
		}
		commit,proof,point := GenerateCommitProofAndPointWithData(data)
		outData := time.Now()
		tm := time.Date(outData.Year(), outData.Month(), outData.Day(), outData.Hour(), 0, 0, 0, outData.Location())
		outTimeStamp := tm.Add(24*time.Hour).Unix()
		// 创建一个上下文，用于取消交易
		var sign1 []byte
		sign1,err = u.signature(u.addr,uint64(index),1024*1024*3,commit,data,das,proof,point,uint64(outTimeStamp))
		if err != nil {
			fmt.Printf("mta_sendDAByParams----send----signUrl:%s ,err:%@",SignUrl,err)
		}
		signStr1 := common.Bytes2Hex(sign1)
		var sign2 []byte
		sign2,err =u.signature2(u.addr,uint64(index),1024*1024*3,commit,data,das,proof,point,uint64(outTimeStamp))
		if err != nil {
			fmt.Printf("mta_sendDAByParams----send----signUrl:%s ,err:%@",SignUrl2,err)
		}
		signStr2 := common.Bytes2Hex(sign2)
		nonce++
		key1 := Key1
		key2 := Key2
		key3 := Key3
		indexStr := strconv.Itoa(index)
		key1 += indexStr
		key2 += indexStr
		key3 += indexStr
		// 以追加的方式写入文件
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key1, signStr1)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key2, signStr2)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		cmStr := common.Bytes2Hex(commit)
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key3, cmStr)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}
	countStr := strconv.Itoa(total)
	fmt.Fprintf(u.localFile, "%s:%s\n", "count", countStr)
}

func (u *UserService) SendDataToExecClient5k() {
	defer u.localFile.Close()
	total := 1024  / 5 + 1
	nonce := u.GetIndex()
	for index := 0;index<total;index++ {
		index := index
		println("当前-----index",index)
		data := make([]byte, 1024*1024*5)
		_, err := rand.Read(data)
		das := common.HexToHash(nodeGroupKeyStr)
		if u.priv == nil || len(u.addr.Bytes()) == 0 {
			priv,addr := PrivateKeyToAddress(u.privStr)
			u.priv = priv
			u.addr = addr
		}
		commit,proof,point := GenerateCommitProofAndPointWithData(data)
		outData := time.Now()
		tm := time.Date(outData.Year(), outData.Month(), outData.Day(), outData.Hour(), 0, 0, 0, outData.Location())
		outTimeStamp := tm.Add(24*time.Hour).Unix()
		var sign1 []byte
		sign1,err = u.signature(u.addr,uint64(index),1024*1024*5,commit,data,das,proof,point,uint64(outTimeStamp))
		if err != nil {
			fmt.Printf("mta_sendDAByParams----send----signUrl:%s ,err:%@",SignUrl,err)
		}
		signStr1 := common.Bytes2Hex(sign1)
		var sign2 []byte
		sign2,err = u.signature2(u.addr,uint64(index),1024*1024*5,commit,data,das,proof,point,uint64(outTimeStamp))
		if err != nil {
			fmt.Printf("mta_sendDAByParams----send----signUrl:%s ,err:%@",SignUrl2,err)
		}
		signStr2 := common.Bytes2Hex(sign2)
		nonce++
		key1 := Key1
		key2 := Key2
		key3 := Key3
		indexStr := strconv.Itoa(index)
		key1 += indexStr
		key2 += indexStr
		key3 += indexStr
		// 以追加的方式写入文件
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key1, signStr1)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key2, signStr2)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		cmstr := common.Bytes2Hex(commit)
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key3, cmstr)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}
	countStr := strconv.Itoa(total)
	fmt.Fprintf(u.localFile, "%s:%s\n", "count", countStr)
}

func (u *UserService) SendDataToExecClient10k() {
	defer u.localFile.Close()
	total :=  1024 / 10 + 1
	nonce := u.GetIndex()
	for index := 0;index<total;index++ {
		index := index
		println("当前-----index",index)
		data := make([]byte, 1024*1024*10)
		_, err := rand.Read(data)
		das := common.HexToHash(nodeGroupKeyStr)
		if u.priv == nil || len(u.addr.Bytes()) == 0 {
			priv,addr := PrivateKeyToAddress(u.privStr)
			u.priv = priv
			u.addr = addr
		}
		commit,proof,point := GenerateCommitProofAndPointWithData(data)
		outData := time.Now()
		tm := time.Date(outData.Year(), outData.Month(), outData.Day(), outData.Hour(), 0, 0, 0, outData.Location())
		outTimeStamp := tm.Add(24*time.Hour).Unix()
		var sign1 []byte
		sign1,err = u.signature(u.addr,uint64(index),1024*1024*10,commit,data,das,proof,point,uint64(outTimeStamp))
		if err != nil {
			fmt.Printf("mta_sendDAByParams----send----signUrl:%s ,err:%@",SignUrl,err)
		}
		signStr1 := common.Bytes2Hex(sign1)
		var sign2 []byte
		sign2,err = u.signature2(u.addr,uint64(index),1024*1024*10,commit,data,das,proof,point,uint64(outTimeStamp))
		if err != nil {
			fmt.Printf("mta_sendDAByParams----send----signUrl:%s ,err:%@",SignUrl2,err)
		}
		signStr2 := common.Bytes2Hex(sign2)
		nonce++
		key1 := Key1
		key2 := Key2
		key3 := Key3
		indexStr := strconv.Itoa(index)
		key1 += indexStr
		key2 += indexStr
		key3 += indexStr
		// 以追加的方式写入文件
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key1, signStr1)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key2, signStr2)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
		cmstr := common.Bytes2Hex(commit)
		_, err = fmt.Fprintf(u.localFile, "%s:%s\n", key3, cmstr)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}
	countStr := strconv.Itoa(total)
	fmt.Fprintf(u.localFile, "%s:%s\n", "count", countStr)
}

func (u *UserService) SendToContract(length uint64) {
	file, err := os.Open("./signInfo.txt")
	if err != nil {
		println("Error opening file for reading",err.Error())
		return
	}
	defer file.Close()
	// 读取文件内容并输出 value 值
	scanner := bufio.NewScanner(file)
	count := 0
	nonce := u.GetIndex()
	var sign1, sign2, commStr string
	var timeout int64
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			key := strings.Trim(parts[0], ` "`)
			value := strings.Trim(parts[1], ` "`)
			str := strconv.Itoa(count / 4 + nonce)
			signStr1 := Key1 + str
			signStr2 := Key2 + str
			cmSte := Key3 + str
			timeStr := Key4 + str
			if strings.Compare(key, signStr1) == 0 {
				sign1 = value
			} else if strings.Compare(key, signStr2) == 0 {
				sign2 = value
			}else if strings.Compare(key, cmSte) == 0 {
				commStr = value
			}else if strings.Compare(key, timeStr) == 0 {
				t,err := strconv.Atoi(value)
				if err != nil {
					println("err",err.Error())
				}
				timeout = int64(t)
			}

			// 每两条记录作为一组输出
			if count % 4 == 3 {
				client,_ := ethclient.Dial(Url)
				fmt.Printf("sign1:%s , sign2:%s , cmmStr:%s  time:%d \n", sign1, sign2, commStr,timeout)
				contractAddress := common.HexToAddress(CommitmentContractAddress)
				instance, err := contract.NewCommitmentManager(contractAddress, client)
				if err != nil {
					errStr := fmt.Sprintf("cant create contract address err:%s", err.Error())
					println("err",errStr)
				}
				auth, err := bind.NewKeyedTransactorWithChainID(u.priv, big.NewInt(ChainID)) // For Mainnet
				if err != nil {
					println("err",err.Error())
				}
				// dasKey  签名所在组织的hash key
				var digest kzg.Digest
				str, _ := hex.DecodeString(commStr)
				digest.SetBytes(str)
				commitData := contract.PairingG1Point{
					X: new(big.Int).SetBytes(digest.X.Marshal()),
					Y: new(big.Int).SetBytes(digest.Y.Marshal()),
				}
				signByte1 := common.Hex2Bytes(sign1)
				signByte2 := common.Hex2Bytes(sign2)
				signs := [][]byte{signByte1,signByte2}
				daskey := common.HexToHash("0x8af361a6d746c89b15a8bce2f9be881e6638b4b17ab7375a89ead3474e341687")
				tx, err := instance.SubmitCommitment(auth, new(big.Int).SetUint64(length*1024), new(big.Int).SetInt64(timeout), common.Hash{} ,daskey, signs, commitData)
				if err != nil {
					log.Fatal(err)
				}
				// 等待交易被打包并获取交易哈希
				fmt.Println("交易哈希:", tx.Hash().Hex())
				// 等待交易被确认
				receipt, err := bind.WaitMined(u.ctx, client, tx)
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
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
}

func GenerateCommitProofAndPointWithData(data []byte) ([]byte, []byte, []byte) {
	currentPath, _ := os.Getwd()
	path := currentPath + "/srs"
	sdk, err := kzgSdk.InitMultiAdaptiveSdk(path)
	if err != nil {
		println("kzg init domicon sdk err", err.Error())
	}
	digst, proof, err := sdk.GenerateDataCommitAndProof(data)
	if err != nil {
		println("GenerateDataCommit ---ERR", err.Error())
	}
	digstData := digst.Marshal()
	claimedValue := proof.ClaimedValue.Marshal()
	return digstData, proof.H.Marshal(), claimedValue
}


func PrivateKeyToAddress(key string) (*ecdsa.PrivateKey, common.Address) {
	privateKey, err := crypto.HexToECDSA(key)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}
	// 创建一个签名交易的发送者
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	return privateKey, fromAddress
}

func main()  {
	startTime := time.Now()
	user := NewUserService(privateKey)
	user.SendDataToExecClient1k()
	//user.SendToContract(1)
	endTime := time.Now()
	println("start time :",startTime.String(),"end time:",endTime.String())
}