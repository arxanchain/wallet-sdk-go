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
	"net/http"
	"reflect"
	"strings"
	"testing"

	pw "github.com/arxanchain/sdk-go-common/protos/wallet"
	"github.com/arxanchain/sdk-go-common/rest"
	"github.com/arxanchain/sdk-go-common/rest/api"
	rtstructs "github.com/arxanchain/sdk-go-common/rest/structs"
	"github.com/arxanchain/sdk-go-common/structs/did"
	"github.com/arxanchain/sdk-go-common/structs/wallet"
	gock "gopkg.in/h2non/gock.v1"
)

var (
	walletClient wallet.IWalletClient
)

func initWalletClient(t *testing.T) {
	client := &http.Client{Transport: &http.Transport{}}
	gock.InterceptClient(client)
	var err error
	walletClient, err = NewWalletClient(&api.Config{Address: "http://127.0.0.1:8006", HttpClient: client})
	if err != nil {
		t.Fatalf("New walletc client fail: %v", err)
	}
}

func initWalletClientWithTrustKeypair(t *testing.T) {
	client := &http.Client{Transport: &http.Transport{}}
	gock.InterceptClient(client)
	var err error
	walletClient, err = NewWalletClient(&api.Config{Address: "http://127.0.0.1:8006", HttpClient: client, TrusteeKeyPairEnable: true})
	if err != nil {
		t.Fatalf("New walletc client fail: %v", err)
	}
}

func TestRegisterSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		id         = "did:axn:001"
		endpoint   = "endpoint-001"
		created    = 88888
		privateKey = "YWRqZmRzYWZrZHNmc2pkZmprd2VqZmpzZGxmanNqZmtsZHNqZmxkc2Zkc2Zkc2ZlZnNkZmRzZjAyMzB1Z29qZGl2bnJzZHNkc2Zkc2Zld2ZzZHNta2pr"
		publicKey  = "OTlmdTJqM25sc2lmMi0tMjA5ZmhzZiB3ZXVvaWpkZmgyaTNoaXdqZWYyMDM5MjgzeQ=="
		token      = "user-token-001"
	)

	//request body & response body
	reqBody := &wallet.RegisterWalletBody{
		Type:   pw.DidType_ORGANIZATION,
		Access: "alice",
		Secret: "123456",
	}
	payload := &wallet.WalletResponse{
		Id:       id,
		Endpoint: endpoint,
		Created:  created,
		KeyPair: &wallet.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
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
		Post("/v1/wallet/register").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do register wallet
	resp, err := walletClient.Register(header, reqBody)
	if err != nil {
		t.Fatalf("register wallet fail: %v", err)
	}
	if resp == nil {
		t.Fatalf("response should not be nil")
	}
	if resp.Id != id {
		t.Fatalf("wallet id should be %v", id)
	}
	if resp.Endpoint != endpoint {
		t.Fatalf("wallet endpoint should be %v", endpoint)
	}
	if resp.Created != created {
		t.Fatalf("wallet created time should be %v", created)
	}
	if resp.KeyPair == nil {
		t.Fatalf("response keypair should not be nil")
	}
	if resp.KeyPair.PrivateKey != privateKey {
		t.Fatalf("private key should be %v", privateKey)
	}
	if resp.KeyPair.PublicKey != publicKey {
		t.Fatalf("public key should be %v", publicKey)
	}
}

func TestRegisterFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		ErrCode = 8005
		ErrMsg  = "create main wallet fail"
	)

	//request body & response body
	reqBody := &wallet.RegisterWalletBody{
		Type:   pw.DidType_ORGANIZATION,
		Access: "alice",
		Secret: "123456",
	}
	respBody := &rtstructs.Response{
		ErrCode:    ErrCode,
		ErrMessage: ErrMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/wallet/register").
		MatchHeader("X-Auth-Token", token).
		Reply(ErrCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do register wallet
	resp, err := walletClient.Register(header, reqBody)
	if err == nil {
		t.Fatalf("register wallet should be fail")
	}
	if !strings.Contains(err.Error(), ErrMsg) {
		t.Fatalf("error message should be return [%s]", ErrMsg)
	}
	if resp != nil {
		t.Fatalf("wallet response object should be nil")
	}
}

func TestRegisterFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		ErrCode = 8005
		ErrMsg  = "create main wallet fail"
	)

	//request body & response body
	reqBody := &wallet.RegisterWalletBody{
		Type:   pw.DidType_ORGANIZATION,
		Access: "alice",
		Secret: "123456",
	}
	respBody := &rtstructs.Response{
		ErrCode:    ErrCode,
		ErrMessage: ErrMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/wallet/register").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do register wallet
	resp, err := walletClient.Register(header, reqBody)
	if err == nil {
		t.Fatalf("register wallet should not be fail")
	}
	errWitherrCode, ok := err.(rest.HTTPCodedError)

	if !ok {
		t.Fatalf("error type should be HTTPCodedError not %v", reflect.TypeOf(err))
	}
	if errWitherrCode.Code() != ErrCode {
		t.Fatalf("Error code should be %d", ErrCode)
	}
	if errWitherrCode.Error() != ErrMsg {
		t.Fatalf("Error message should be %s", ErrMsg)
	}
	if resp != nil {
		t.Fatalf("wallet response object should be nil")
	}
}

func TestRegisterSubWalletSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		id         = "did:axn:001"
		endpoint   = "endpoint-001"
		created    = 88888
		privateKey = "YWRqZmRzYWZrZHNmc2pkZmprd2VqZmpzZGxmanNqZmtsZHNqZmxkc2Zkc2Zkc2ZlZnNkZmRzZjAyMzB1Z29qZGl2bnJzZHNkc2Zkc2Zld2ZzZHNta2pr"
		publicKey  = "OTlmdTJqM25sc2lmMi0tMjA5ZmhzZiB3ZXVvaWpkZmgyaTNoaXdqZWYyMDM5MjgzeQ=="
		token      = "user-token-001"
	)

	//request body & response body
	reqBody := &wallet.RegisterSubWalletBody{
		Id:   "did:axn:001",
		Type: pw.DidType_SWCASH,
	}
	payload := &wallet.WalletResponse{
		Id:       id,
		Endpoint: endpoint,
		Created:  created,
		KeyPair: &wallet.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
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
		Post("/v1/wallet/register/subwallet").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do register wallet
	resp, err := walletClient.RegisterSubWallet(header, reqBody)
	if err != nil {
		t.Fatalf("register wallet fail: %v", err)
	}
	if resp == nil {
		t.Fatalf("response should not be nil")
	}
	if resp.Id != id {
		t.Fatalf("wallet id should be %v", id)
	}
	if resp.Endpoint != endpoint {
		t.Fatalf("wallet endpoint should be %v", endpoint)
	}
	if resp.Created != created {
		t.Fatalf("wallet created time should be %v", created)
	}
	if resp.KeyPair == nil {
		t.Fatalf("response keypair should not be nil")
	}
	if resp.KeyPair.PrivateKey != privateKey {
		t.Fatalf("private key should be %v", privateKey)
	}
	if resp.KeyPair.PublicKey != publicKey {
		t.Fatalf("public key should be %v", publicKey)
	}
}

func TestRegisterSubWalletFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		ErrCode = 8005
		ErrMsg  = "create sub wallet fail"
	)

	//request body & response body
	reqBody := &wallet.RegisterSubWalletBody{
		Id:   "did:axn:001",
		Type: pw.DidType_SWCASH,
	}
	respBody := &rtstructs.Response{
		ErrCode:    ErrCode,
		ErrMessage: ErrMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/wallet/register/subwallet").
		MatchHeader("X-Auth-Token", token).
		Reply(ErrCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do register wallet
	resp, err := walletClient.RegisterSubWallet(header, reqBody)
	if err == nil {
		t.Fatalf("register wallet should be fail")
	}
	if !strings.Contains(err.Error(), ErrMsg) {
		t.Fatalf("error message should be return [%s]", ErrMsg)
	}
	if resp != nil {
		t.Fatalf("wallet response object should be nil")
	}
}

func TestRegisterSubWalletFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		ErrCode = 8005
		ErrMsg  = "create sub wallet fail"
	)

	//request body & response body
	reqBody := &wallet.RegisterSubWalletBody{
		Id:   "did:axn:001",
		Type: pw.DidType_SWCASH,
	}
	respBody := &rtstructs.Response{
		ErrCode:    ErrCode,
		ErrMessage: ErrMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Post("/v1/wallet/register/subwallet").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do register wallet
	resp, err := walletClient.RegisterSubWallet(header, reqBody)
	if err == nil {
		t.Fatalf("register wallet should not be fail")
	}

	errWitherrCode, ok := err.(rest.HTTPCodedError)
	if !ok {
		t.Fatalf("error type should be HTTPCodedError not %v", reflect.TypeOf(err))
	}
	if errWitherrCode.Code() != ErrCode {
		t.Fatalf("Error code should be %d", ErrCode)
	}
	if errWitherrCode.Error() != ErrMsg {
		t.Fatalf("Error message should be %s", ErrMsg)
	}
	if resp != nil {
		t.Fatalf("wallet response object should be nil")
	}
}

func TestGetWalletBalanceSucc(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		id          = "did:axn:001"
		token       = "user-token-001"
		tokenID     = "colored-token-001"
		tokenAmount = 5000
		assetID     = "asset-id-002"
	)

	//build response body
	payload := &wallet.WalletBalance{
		ColoredTokens: map[string]*wallet.Balance{
			tokenID: {
				Id:     tokenID,
				Amount: tokenAmount,
			},
		},
		DigitalAssets: map[string]*wallet.Balance{
			assetID: {
				Id:     assetID,
				Amount: 1,
			},
		},
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
		Get("/v1/wallet/balance").
		MatchParam("id", id).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.GetWalletBalance(header, id)
	if err != nil {
		t.Fatalf("get wallet balance fail: %v", err)
	}
	if result == nil {
		t.Fatalf("response balance object should not be nil")
	}
	if result.ColoredTokens == nil || len(result.ColoredTokens) == 0 {
		t.Fatalf("colored tokens should not be nil")
	}
	if result.DigitalAssets == nil || len(result.DigitalAssets) == 0 {
		t.Fatalf("digital assets should not be nil")
	}
	ctoken, ok := result.ColoredTokens[tokenID]
	if !ok || ctoken == nil {
		t.Fatalf("colored token(%v) should exist", tokenID)
	}
	if ctoken.Amount != tokenAmount {
		t.Fatalf("colored token(%v) amount should be %v", tokenID, tokenAmount)
	}
	asset, ok := result.DigitalAssets[assetID]
	if !ok || asset == nil {
		t.Fatalf("asset(%v) should exist", assetID)
	}
	if asset.Amount != 1 {
		t.Fatalf("asset(%v) amount should be %v", assetID, 1)
	}
}

func TestGetWalletBalanceFail(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		id      = "did:axn:001"
		token   = "user-token-001"
		errCode = 8001
		errMsg  = "get colored token error"
	)

	//build response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Get("/v1/wallet/balance").
		MatchParam("id", id).
		Reply(errCode).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.GetWalletBalance(header, id)
	if err == nil {
		t.Fatalf("err should not be nil when query fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("error message should contains [%v]", errMsg)
	}
	if result != nil {
		t.Fatalf("WalletBalance object should be nil when query fail")
	}
}

func TestGetWalletBalanceFailErrCode(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		id      = "did:axn:001"
		token   = "user-token-001"
		errCode = 8001
		errMsg  = "get colored token error"
	)

	//build response body
	respBody := &rtstructs.Response{
		ErrCode:    errCode,
		ErrMessage: errMsg,
	}

	//mock http request
	gock.New("http://127.0.0.1:8006").
		Get("/v1/wallet/balance").
		MatchParam("id", id).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.GetWalletBalance(header, id)
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
		t.Fatalf("WalletBalance object should be nil when query fail")
	}
}

func TestGetWalletInfoSucc(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token      = "user-token-001"
		id         = did.Identifier("did:axn:001")
		endpoint   = did.DidEndpoint("endpoint-001")
		walletType = pw.DidType_ORGANIZATION
	)

	//build response body
	payload := &wallet.WalletInfo{
		Id:       id,
		Type:     walletType,
		Endpoint: endpoint,
		Status:   pw.Status_VALID,
		Created:  55555,
		Updated:  66666,
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
		Get("/v1/wallet/info").
		MatchParam("id", string(id)).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.GetWalletInfo(header, id)
	if err != nil {
		t.Fatalf("get wallet info fail: %v", err)
	}
	if result == nil {
		t.Fatalf("WalletInfo object should not be nil")
	}
	if result.Id != id {
		t.Fatalf("wallet id should be %v", id)
	}
	if result.Type != walletType {
		t.Fatalf("wallet type should be %v", walletType)
	}
	if result.Endpoint != endpoint {
		t.Fatalf("wallet endpoint should be %v", endpoint)
	}
	if result.Status != pw.Status_VALID {
		t.Fatalf("wallet status should be %v", pw.Status_VALID)
	}
}

func TestGetWalletInfoFail(t *testing.T) {
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
		Get("/v1/wallet/info").
		MatchParam("id", id).
		Reply(errCode).
		JSON(respBody)

		//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.GetWalletInfo(header, id)
	if err == nil {
		t.Fatalf("err should not be nil when query fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("error message should contains [%v]", errMsg)
	}
	if result != nil {
		t.Fatalf("WalletInfo object should be nil when query fail")
	}
}

func TestGetWalletInfoFailErrCode(t *testing.T) {
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
		Get("/v1/wallet/info").
		MatchParam("id", id).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.GetWalletInfo(header, id)
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
		t.Fatalf("WalletInfo object should be nil when query fail")
	}
}
