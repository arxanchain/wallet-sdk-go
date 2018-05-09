/*
Copyright ArxanFintech Technology Ltd. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/arxanchain/sdk-go-common/errors"
	"github.com/arxanchain/sdk-go-common/rest"
	restapi "github.com/arxanchain/sdk-go-common/rest/api"
	rtstructs "github.com/arxanchain/sdk-go-common/rest/structs"
	"github.com/arxanchain/sdk-go-common/structs"
)

// WalletClient is a http agent to wallet service.
//
type WalletClient struct {
	c *restapi.Client
}

// NewWalletClient returns a WalletClient instance.
//
func NewWalletClient(config *restapi.Config) (*WalletClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config must be set")
	}
	if config.RouteTag == "" {
		config.RouteTag = "wallet-ng"
	}

	c, err := restapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &WalletClient{c: c}, nil
}

// Register is used to register user wallet.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
func (w *WalletClient) Register(header http.Header, body *structs.RegisterWalletBody) (result *structs.WalletResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/wallet/register")
	r.SetHeaders(header)
	r.SetBody(body)

	// Do http request
	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return
	}

	payload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(payload), &result)

	return
}

// RegisterSubWallet is used to register user subwallet.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
func (w *WalletClient) RegisterSubWallet(header http.Header, body *structs.RegisterSubWalletBody) (result *structs.WalletResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/wallet/register/subwallet")
	r.SetHeaders(header)
	r.SetBody(body)

	// Do http request
	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return
	}

	payload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(payload), &result)

	return
}

// GetWalletBalance is used to get wallet balances.
//
func (w *WalletClient) GetWalletBalance(header http.Header, id structs.Identifier) (result *structs.WalletBalance, err error) {
	r := w.c.NewRequest("GET", "/v1/wallet/balance")
	r.SetHeaders(header)
	r.SetParam("id", string(id))

	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return
	}

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(respPayload), &result)

	return
}

// GetWalletInfo is used to get wallet base information.
//
func (w *WalletClient) GetWalletInfo(header http.Header, id structs.Identifier) (result *structs.WalletInfo, err error) {
	r := w.c.NewRequest("GET", "/v1/wallet/info")
	r.SetHeaders(header)
	r.SetParam("id", string(id))

	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return
	}

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(respPayload), &result)

	return
}
