package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
)

// 功能：调用其他模块API并获取返回结果
func CURLPerform(method string, url string, body map[string]interface{}, strBody string) (*simplejson.Json, error) {
	errResponse, _ := simplejson.NewJson([]byte("{}"))

	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: time.Second * 30}

	var err error
	var contentType string
	req := &http.Request{}
	if strBody != "" {
		reader := strings.NewReader(strBody)
		req, err = http.NewRequest(method, url, reader)
		contentType = "application/x-www-form-urlencoded"
	} else {
		bodyStr, _ := json.Marshal(&body)
		reader := bytes.NewReader(bodyStr)
		req, err = http.NewRequest(method, url, reader)
		contentType = "application/json"
	}

	if err != nil {
		return errResponse, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Type", "1")

	resp, err := client.Do(req)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", url, err))
	} else if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", url, resp))
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("read (%s) body failed, (%v)", url, err))
	}

	response, err := simplejson.NewJson(respBytes)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("parse (%s) body failed, (%v)", url, err))
	}

	optStatus := response.Get("OPT_STATUS").MustString()
	if optStatus != "" && optStatus != SUCCESS {
		description := response.Get("DESCRIPTION").MustString()
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%s)", url, description))
	}

	return response, nil
}
