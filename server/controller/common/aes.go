package common

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"google.golang.org/grpc"

	"github.com/deepflowio/deepflow/message/controller"
)

var CAMD5 string

func init() {
	CAMD5 = getCAMD5()
}

func GenerateAesKey(input []byte) string {
	return fmt.Sprintf("%x", md5.Sum(input))
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	len := len(origData)
	unpadding := int(origData[len-1])
	if (len - unpadding) < 0 {
		return nil
	}
	return origData[:(len - unpadding)]
}

func AesEncrypt(origDataStr, keyStr string) (string, error) {
	key := []byte(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData := PKCS7Padding([]byte(origDataStr), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

func AesDecrypt(cryptedStr, keyStr string) (string, error) {
	key := []byte(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	crypted, err := base64.StdEncoding.DecodeString(cryptedStr)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	if len(crypted)%blockSize != 0 {
		return "", errors.New("input is not encrypt key")
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	if origData == nil {
		return "", errors.New("encrypt key failed")
	}
	return string(origData), nil
}

func GetEncryptKey(controllerIP, grpcServerPort, key string) (string, error) {
	grpcServer := net.JoinHostPort(controllerIP, grpcServerPort)
	conn, err := grpc.Dial(grpcServer, grpc.WithInsecure())
	if err != nil {
		log.Error("create grpc connection faild:" + err.Error())
		return "", err
	}
	defer conn.Close()

	client := controller.NewControllerClient(conn)
	ret, err := client.GetEncryptKey(
		context.Background(),
		&controller.EncryptKeyRequest{Key: &key},
	)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return ret.GetEncryptKey(), nil
}

func EncryptSecretKey(secretKey string) (string, error) {
	caData, err := ioutil.ReadFile(K8S_CA_CRT_PATH)
	if err != nil {
		log.Error(err)
		return "", err
	}
	aesKey := GenerateAesKey(caData)
	encryptSecretKey, err := AesEncrypt(secretKey, aesKey)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return encryptSecretKey, nil
}

func DecryptSecretKey(secretKey string) (string, error) {
	caData, err := ioutil.ReadFile(K8S_CA_CRT_PATH)
	if err != nil {
		log.Error(err)
		return "", err
	}
	aesKey := GenerateAesKey(caData)
	decryptSecretKey, err := AesDecrypt(secretKey, aesKey)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return decryptSecretKey, nil
}

func GetLocalClusterID() (string, error) {
	caData, err := ioutil.ReadFile(K8S_CA_CRT_PATH)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return GenerateKuberneteClusterIDByMD5(GenerateAesKey(caData))
}

func getCAMD5() string {
	caData, err := ioutil.ReadFile(K8S_CA_CRT_PATH)
	if err != nil {
		log.Error(err)
		return ""
	}
	return GenerateAesKey(caData)
}

func GetCAMD5() string {
	return CAMD5
}
