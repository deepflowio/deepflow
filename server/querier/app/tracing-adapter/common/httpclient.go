/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/config"
	"github.com/goccy/go-json"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("tracing-adapter.common")

func DefaultContentTypeHeader() map[string]string {
	return map[string]string{
		"Content-Type": "application/json",
	}
}

func Serialize[T any](obj T) ([]byte, error) {
	result, err := json.Marshal(obj)
	return result, err
}

func Deserialize[T any](data []byte) (*T, error) {
	var result T
	err := json.Unmarshal(data, &result)
	return &result, err
}

func prepareRequest(timeout time.Duration, tlsConfig *config.TLSConfig) (*http.Client, error) {
	client := &http.Client{}
	http.DefaultClient.Timeout = timeout
	if tlsConfig != nil {
		tlsClientConfig := &tls.Config{}
		if tlsConfig.Insecure {
			tlsClientConfig.InsecureSkipVerify = true
		} else {
			clientTLSCert, err := tls.LoadX509KeyPair(tlsConfig.CertFile, tlsConfig.KeyFile)
			if err != nil {
				log.Errorf("load cert file fot tls verification false! err: %s", err)
				return nil, err
			}
			certPool, err := x509.SystemCertPool()
			if err != nil {
				log.Errorf("create cert pool false! err: %s", err)
				return nil, err
			}
			caCertPEM, err := os.ReadFile(tlsConfig.CAFile)
			if err != nil {
				log.Errorf("read ca file false! err: %s", err)
				return nil, err
			}

			if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
				log.Errorf("invalid cert for CA PEM! err: %s", err)
				return nil, err
			}
			tlsClientConfig.RootCAs = certPool
			tlsClientConfig.Certificates = []tls.Certificate{clientTLSCert}
		}

		http.DefaultClient.Transport = &http.Transport{TLSClientConfig: tlsClientConfig}
	}
	return client, nil
}

func DoRequest(method string, addr string, body []byte, headers map[string]string, timeout time.Duration, tlsConfig *config.TLSConfig) ([]byte, error) {
	client, err := prepareRequest(timeout, tlsConfig)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, addr, bytes.NewReader(body))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("http client do request at %s, error: %s", addr, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("http client request: %s failed, response detail: %+v", addr, resp)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("read (%s) body failed, (%v)", addr, err)
		return nil, err
	}

	return respBytes, nil
}
