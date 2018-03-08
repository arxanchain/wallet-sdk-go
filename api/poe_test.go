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
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/arxanchain/sdk-go-common/rest"
	rtstructs "github.com/arxanchain/sdk-go-common/rest/structs"
	"github.com/arxanchain/sdk-go-common/structs"
	gock "gopkg.in/h2non/gock.v1"
)

func TestCreatePOESucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token         = "user-token-001"
		poeID         = "did:axn:poe-id-001"
		created int64 = 5555555
		transID       = "trans-id-001"
	)

	//request body & response body
	reqBody := &structs.POEBody{
		Name:     "piaoju001",
		Owner:    "did:axn:001",
		Metadata: []byte("this is metadata"),
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	payload := &structs.WalletResponse{
		Id:             poeID,
		Created:        created,
		TransactionIds: []string{transID},
	}
	byPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("%v", err)
	}
	respBody := &rtstructs.Response{
		ErrCode: 0,
		Payload: string(byPayload),
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/poe/create").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do create poe asset
	resp, err := walletClient.CreatePOE(header, reqBody, sign)
	if err != nil {
		t.Fatalf("create poe asset fail: %v", err)
	}
	if resp == nil {
		t.Fatalf("response should not be nil")
	}
	if len(resp.TransactionIds) == 0 {
		t.Fatalf("response transaction list should not be empty")
	}
	if resp.TransactionIds[0] != transID {
		t.Fatalf("response transaction id should be %v", transID)
	}
	if resp.Id != poeID {
		t.Fatalf("response POE asset id should be %v", poeID)
	}
	if resp.Created != created {
		t.Fatalf("response created time should be %v", created)
	}
}

func TestCreatePOEFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	//request body & response body
	reqBody := &structs.POEBody{
		Name:     "piaoju001",
		Owner:    "did:axn:001",
		Metadata: []byte("this is metadata"),
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/poe/create").
		MatchHeader("X-Auth-Token", token).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do create poe asset
	resp, err := walletClient.CreatePOE(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when creating poe asset fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if resp != nil {
		t.Fatalf("response object should be nil when creating poe asset fail")
	}
}

func TestCreatePOEFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	//request body & response body
	reqBody := &structs.POEBody{
		Name:     "piaoju001",
		Owner:    "did:axn:001",
		Metadata: []byte("this is metadata"),
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/poe/create").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do create poe asset
	resp, err := walletClient.CreatePOE(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when creating poe asset fail")
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

	if resp != nil {
		t.Fatalf("response object should be nil when creating poe asset fail")
	}
}

func TestUpdatePOESucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		transID = "trans-id-001"
	)

	//request body & response body
	reqBody := &structs.POEBody{
		Id:       "did:axn:poe-id-001",
		Name:     "piaoju001",
		Owner:    "did:axn:001",
		Metadata: []byte("this is metadata"),
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	payload := &structs.WalletResponse{
		TransactionIds: []string{transID},
	}
	byPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("%v", err)
	}
	respBody := &rtstructs.Response{
		ErrCode: 0,
		Payload: string(byPayload),
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Put("/v1/poe/update").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do create poe asset
	resp, err := walletClient.UpdatePOE(header, reqBody, sign)
	if err != nil {
		t.Fatalf("create poe asset fail: %v", err)
	}
	if resp == nil {
		t.Fatalf("response should not be nil")
	}
	if len(resp.TransactionIds) == 0 {
		t.Fatalf("response transaction list should not be empty")
	}
	if resp.TransactionIds[0] != transID {
		t.Fatalf("response transaction id should be %v", transID)
	}
}

func TestUpdatePOEFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	//request body & response body
	reqBody := &structs.POEBody{
		Id:       "did:axn:poe-id-001",
		Name:     "piaoju001",
		Owner:    "did:axn:001",
		Metadata: []byte("this is metadata"),
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Put("/v1/poe/update").
		MatchHeader("X-Auth-Token", token).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do create poe asset
	resp, err := walletClient.UpdatePOE(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when updating poe asset fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if resp != nil {
		t.Fatalf("response object should be nil when updating poe asset fail")
	}
}

func TestUpdatePOEFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	//request body & response body
	reqBody := &structs.POEBody{
		Id:       "did:axn:poe-id-001",
		Name:     "piaoju001",
		Owner:    "did:axn:001",
		Metadata: []byte("this is metadata"),
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Put("/v1/poe/update").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do create poe asset
	resp, err := walletClient.UpdatePOE(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when updating poe asset fail")
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

	if resp != nil {
		t.Fatalf("response object should be nil when updating poe asset fail")
	}
}

func TestQueryPOESucc(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token    = "user-token-001"
		id       = structs.Identifier("did:axn:001")
		name     = "MyCar"
		owner    = structs.Identifier("did:axn:poe-owner-id")
		metadata = "this is asset metadata"
		created  = 55555
		updated  = 66666
	)

	//build response body
	payload := &structs.POEPayload{
		Id:       id,
		Name:     name,
		Owner:    owner,
		Metadata: []byte(metadata),
		Created:  created,
		Updated:  updated,
		Status:   structs.DSValid,
	}
	byPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("%v", err)
	}
	respBody := &rtstructs.Response{
		ErrCode: 0,
		Payload: string(byPayload),
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Get("/v1/poe").
		MatchParam("id", string(id)).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.QueryPOE(header, id)
	if err != nil {
		t.Fatalf("query poe asset fail: %v", err)
	}
	if result == nil {
		t.Fatalf("POEPayload object should not be nil")
	}
	if result.Id != id {
		t.Fatalf("poe id should be %v", id)
	}
	if result.Name != name {
		t.Fatalf("poe name should be %v", name)
	}
	if result.Owner != owner {
		t.Fatalf("poe owner should be %v", owner)
	}
	if string(result.Metadata) != metadata {
		t.Fatalf("poe metadata should be %v", metadata)
	}
	if result.Created != created {
		t.Fatalf("poe created time should be %v", created)
	}
	if result.Updated != updated {
		t.Fatalf("poe updated time should be %v", updated)
	}
	if result.Status != structs.DSValid {
		t.Fatalf("poe status should be %v", structs.DSValid)
	}
}

func TestQueryPOEFail(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		id      = "did:axn:001"
		token   = "user-token-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	//build response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Get("/v1/poe").
		MatchParam("id", id).
		Reply(errCode).
		JSON(respBody)

		//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.QueryPOE(header, id)
	if err == nil {
		t.Fatalf("err should not be nil when query fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("error message should contains [%v]", errMsg)
	}
	if result != nil {
		t.Fatalf("POEPayload object should be nil when query fail")
	}
}

func TestQueryPOEFailErrCode(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		id      = "did:axn:001"
		token   = "user-token-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	//build response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Get("/v1/poe").
		MatchParam("id", id).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.QueryPOE(header, id)
	if err == nil {
		t.Fatalf("err should not be nil when query fail")
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
	if result != nil {
		t.Fatalf("POEPayload object should be nil when query fail")
	}
}

func TestUploadPOEFileSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		poeID   = "did:axn:poe-id-001"
		transID = "trans-id-001"
	)

	poeFile, err := createFile()
	if err != nil {
		t.Fatalf("create tmp file fail: %v", err)
	}
	defer os.Remove(poeFile) // clean up

	payload := &structs.WalletResponse{
		Id:             poeID,
		TransactionIds: []string{transID},
	}
	byPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("%v", err)
	}
	respBody := &rtstructs.Response{
		ErrCode: 0,
		Payload: string(byPayload),
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/poe/upload").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do create poe asset
	resp, err := walletClient.UploadPOEFile(header, poeID, poeFile)
	if err != nil {
		t.Fatalf("create poe asset fail: %v", err)
	}
	if resp == nil {
		t.Fatalf("response should not be nil")
	}
	if len(resp.TransactionIds) == 0 {
		t.Fatalf("response transaction list should not be empty")
	}
	if resp.TransactionIds[0] != transID {
		t.Fatalf("response transaction id should be %v", transID)
	}
	if resp.Id != poeID {
		t.Fatalf("response POE asset id should be %v", poeID)
	}
}

func TestUploadPOEFileFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		poeID   = "did:axn:poe-id-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	poeFile, err := createFile()
	if err != nil {
		t.Fatalf("create tmp file fail: %v", err)
	}
	defer os.Remove(poeFile) // clean up

	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/poe/upload").
		MatchHeader("X-Auth-Token", token).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do create poe asset
	resp, err := walletClient.UploadPOEFile(header, poeID, poeFile)
	if err == nil {
		t.Fatalf("err should not be nil when creating poe asset fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if resp != nil {
		t.Fatalf("response object should be nil when creating poe asset fail")
	}
}

func TestUploadPOEFileFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		poeID   = "did:axn:poe-id-001"
		errCode = 8000
		errMsg  = "wallet not found"
	)

	poeFile, err := createFile()
	if err != nil {
		t.Fatalf("create tmp file fail: %v", err)
	}
	defer os.Remove(poeFile) // clean up

	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/poe/upload").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do create poe asset
	resp, err := walletClient.UploadPOEFile(header, poeID, poeFile)
	if err == nil {
		t.Fatalf("err should not be nil when creating poe asset fail")
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
	if resp != nil {
		t.Fatalf("response object should be nil when creating poe asset fail")
	}
}

func createFile() (string, error) {
	// Create a temporary file for upload
	str := "temporary file's content"
	content := []byte(str)
	tmpfile, err := ioutil.TempFile("", "test")
	if err != nil {
		return "", err
	}
	if _, err1 := tmpfile.Write(content); err1 != nil {
		return "", err1
	}
	if err2 := tmpfile.Close(); err2 != nil {
		return "", err2
	}
	return tmpfile.Name(), nil
}
