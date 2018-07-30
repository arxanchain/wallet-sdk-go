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
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/arxanchain/sdk-go-common/rest"
	rtstructs "github.com/arxanchain/sdk-go-common/rest/structs"
	"github.com/arxanchain/sdk-go-common/structs/wallet"
	gock "gopkg.in/h2non/gock.v1"
)

func TestIndexSetSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		apiKey  = "Mb2mwHnHp1530085974"
		did     = "did:axn:8uQhQMGzWxR8vw5P3UWH1j"
		transID = "trans-id-001"
	)

	// mock request body
	reqBody := &wallet.IndexSetPayload{
		Id: did,
		Indexs: &wallet.IndexTags{
			CombinedIndex:   []string{"first-keyword", "second-keyword", "third-keyword"},
			IndividualIndex: []string{"first-individual-index", "second-individual-index"},
		},
	}

	// mock response body
	respPayload := []string{transID}
	respPayloadBytes, err := json.Marshal(respPayload)
	if err != nil {
		t.Fatalf("%v", err)
	}
	respBody := &rtstructs.Response{
		ErrCode: 0,
		Payload: string(respPayloadBytes),
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/index/set").
		MatchHeader("API-Key", apiKey).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("API-Key", apiKey)

	//do create poe asset
	txIDs, err := walletClient.IndexSet(header, reqBody)
	if err != nil {
		t.Fatalf("index set fail: %v", err)
	}
	if txIDs == nil {
		t.Fatalf("response should not be nil")
	}
	if len(txIDs) != 1 {
		t.Fatalf("response should be an array which contains one transaction id")
	}
	if txIDs[0] != transID {
		t.Fatalf("response transaction id should be %v", transID)
	}
}

func TestIndexSetFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		apiKey  = "Mb2mwHnHp1530085974"
		did     = "did:axn:8uQhQMGzWxR8vw5P3UWH1j"
		errCode = 8000
		errMsg  = "did not found"
	)

	// mock request body
	reqBody := &wallet.IndexSetPayload{
		Id: did,
		Indexs: &wallet.IndexTags{
			CombinedIndex:   []string{"first-keyword", "second-keyword", "third-keyword"},
			IndividualIndex: []string{"first-individual-index", "second-individual-index"},
		},
	}

	// mock response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/index/set").
		MatchHeader("API-Key", apiKey).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("API-Key", apiKey)

	//do create poe asset
	txIDs, err := walletClient.IndexSet(header, reqBody)
	if err == nil {
		t.Fatalf("err should not be nil when index set fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if txIDs != nil {
		t.Fatalf("response should be nil when index set fail")
	}
}

func TestIndexSetFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		apiKey  = "Mb2mwHnHp1530085974"
		did     = "did:axn:8uQhQMGzWxR8vw5P3UWH1j"
		errCode = 8000
		errMsg  = "did not found"
	)

	// mock request body
	reqBody := &wallet.IndexSetPayload{
		Id: did,
		Indexs: &wallet.IndexTags{
			CombinedIndex:   []string{"first-keyword", "second-keyword", "third-keyword"},
			IndividualIndex: []string{"first-individual-index", "second-individual-index"},
		},
	}

	// mock response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/index/set").
		MatchHeader("API-Key", apiKey).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("API-Key", apiKey)

	//do create poe asset
	txIDs, err := walletClient.IndexSet(header, reqBody)
	if err == nil {
		t.Fatalf("err should not be nil when index set fail")
	}
	errWitherrCode, ok := err.(rest.HTTPCodedError)
	if !ok {
		t.Fatalf("error type should be HTTPCodedError not %v", reflect.TypeOf(err))
	}
	if errWitherrCode.Code() != errCode {
		t.Fatalf("Error code should be %d", errCode)
	}
	if errWitherrCode.Error() != errMsg {
		t.Fatalf("Error message should be %s", errMsg)
	}
	if txIDs != nil {
		t.Fatalf("response should be nil when index set fail")
	}
}

func TestIndexGetSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		apiKey = "Mb2mwHnHp1530085974"
		did    = "did:axn:8uQhQMGzWxR8vw5P3UWH1j"
	)

	// mock request body
	reqBody := &wallet.IndexGetPayload{
		Indexs: &wallet.IndexTags{
			CombinedIndex:   []string{"first-keyword", "second-keyword", "third-keyword"},
			IndividualIndex: []string{"first-individual-index", "second-individual-index"},
		},
	}

	// mock response body
	respPayload := []string{did}
	respPayloadBytes, err := json.Marshal(respPayload)
	if err != nil {
		t.Fatalf("%v", err)
	}
	respBody := &rtstructs.Response{
		ErrCode: 0,
		Payload: string(respPayloadBytes),
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/index/get").
		MatchHeader("API-Key", apiKey).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("API-Key", apiKey)

	//do create poe asset
	ids, err := walletClient.IndexGet(header, reqBody)
	if err != nil {
		t.Fatalf("index get fail: %v", err)
	}
	if ids == nil {
		t.Fatalf("response should not be nil")
	}
	if len(ids) != 1 {
		t.Fatalf("response should be an array which contains one object id")
	}
	if ids[0] != did {
		t.Fatalf("response object id should be %v", did)
	}
}

func TestIndexGetFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		apiKey  = "Mb2mwHnHp1530085974"
		errCode = 8001
		errMsg  = "index not found"
	)

	// mock request body
	reqBody := &wallet.IndexGetPayload{
		Indexs: &wallet.IndexTags{
			CombinedIndex:   []string{"first-keyword", "second-keyword", "third-keyword"},
			IndividualIndex: []string{"first-individual-index", "second-individual-index"},
		},
	}

	// mock response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/index/get").
		MatchHeader("API-Key", apiKey).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("API-Key", apiKey)

	//do create poe asset
	ids, err := walletClient.IndexGet(header, reqBody)
	if err == nil {
		t.Fatalf("err should not be nil when index get fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if ids != nil {
		t.Fatalf("response should be nil when index get fail")
	}
}

func TestIndexGetFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		apiKey  = "Mb2mwHnHp1530085974"
		errCode = 8001
		errMsg  = "index not found"
	)

	// mock request body
	reqBody := &wallet.IndexGetPayload{
		Indexs: &wallet.IndexTags{
			CombinedIndex:   []string{"first-keyword", "second-keyword", "third-keyword"},
			IndividualIndex: []string{"first-individual-index", "second-individual-index"},
		},
	}

	// mock response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/index/get").
		MatchHeader("API-Key", apiKey).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("API-Key", apiKey)

	//do create poe asset
	ids, err := walletClient.IndexGet(header, reqBody)
	if err == nil {
		t.Fatalf("err should not be nil when index get fail")
	}
	errWitherrCode, ok := err.(rest.HTTPCodedError)
	if !ok {
		t.Fatalf("error type should be HTTPCodedError not %v", reflect.TypeOf(err))
	}
	if errWitherrCode.Code() != errCode {
		t.Fatalf("Error code should be %d", errCode)
	}
	if errWitherrCode.Error() != errMsg {
		t.Fatalf("Error message should be %s", errMsg)
	}
	if ids != nil {
		t.Fatalf("response should be nil when index get fail")
	}
}
