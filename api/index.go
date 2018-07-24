/*
Copyright ArxanFintech Technology Ltd. 2018 All Rights Reserved.

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
	"github.com/arxanchain/sdk-go-common/structs/wallet"
)

// IndexSet is used to create indexs for object-id
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
func (w *WalletClient) IndexSet(header http.Header, body *wallet.IndexSetPayload) (txIDs []string, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/index/set")
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

	err = json.Unmarshal([]byte(payload), &txIDs)

	return
}

// IndexGet is used to query object-id via indexs
//
func (w *WalletClient) IndexGet(header http.Header, body *wallet.IndexGetPayload) (IDs []string, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/index/get")
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

	err = json.Unmarshal([]byte(payload), &IDs)

	return
}
