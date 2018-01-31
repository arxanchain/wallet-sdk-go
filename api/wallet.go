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

// WalletClient is a http agent to wallet service
type WalletClient struct {
	c *restapi.Client
}

// NewWalletClient returns a WalletClient instance
func NewWalletClient(config *restapi.Config) (*WalletClient, error) {
	c, err := restapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &WalletClient{c: c}, nil
}

// Register is used to register user wallet
func (w *WalletClient) Register(header http.Header, body *structs.RegisterWalletBody) (result *structs.WalletResponse, err error) {
	// build http request
	r := w.c.NewRequest("POST", "/v1/wallet/register")
	r.SetHeaders(header)
	r.SetBody(body)

	// do http request
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

	payload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(payload), &result)

	return
}

// RegisterSubWallet is used to register user subwallet
func (w *WalletClient) RegisterSubWallet(header http.Header, body *structs.RegisterSubWalletBody) (result *structs.WalletResponse, err error) {
	// build http request
	r := w.c.NewRequest("POST", "/v1/wallet/register/subwallet")
	r.SetHeaders(header)
	r.SetBody(body)

	// do http request
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

	payload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(payload), &result)

	return
}

// TransferCToken is used to transfer colored tokens from one user to another
func (w *WalletClient) TransferCToken(header http.Header, body *structs.TransferBody, sign *structs.SignatureBody) (result *structs.WalletResponse, err error) {
	// build http request
	r := w.c.NewRequest("POST", "/v1/transaction/tokens/transfer")
	r.SetHeaders(header)

	reqPayload, err := json.Marshal(body)
	if err != nil {
		return
	}
	reqBody := &structs.WalletRequest{
		Payload:   string(reqPayload),
		Signature: sign,
	}
	r.SetBody(reqBody)

	// do http request
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

// TransferAsset is used to transfer assets from one user to another
func (w *WalletClient) TransferAsset(header http.Header, body *structs.TransferAssetBody, sign *structs.SignatureBody) (result *structs.WalletResponse, err error) {
	// build http request
	r := w.c.NewRequest("POST", "/v1/transaction/assets/transfer")
	r.SetHeaders(header)

	reqPayload, err := json.Marshal(body)
	if err != nil {
		return
	}
	reqBody := &structs.WalletRequest{
		Payload:   string(reqPayload),
		Signature: sign,
	}
	r.SetBody(reqBody)

	// do http request
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

// GetWalletBalance is used to get wallet balances
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

// GetWalletInfo is used to get wallet base information
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
