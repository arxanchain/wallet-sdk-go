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
	"github.com/arxanchain/sdk-go-common/structs"
	gock "gopkg.in/h2non/gock.v1"
)

func TestIssueCTokenSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token    = "user-token-001"
		ctokenID = "colored-token-id-001"
		transID  = "trans-id-001"
	)

	//request body & response body
	reqBody := &structs.IssueBody{
		Issuer:  "did:axn:001",
		Owner:   "did:axn:002",
		AssetId: "asset-id-001",
		Amount:  1000,
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	payload := &structs.WalletResponse{
		CoinId:         ctokenID,
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
		Post("/v1/transaction/tokens/issue").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do issue colored token
	resp, err := walletClient.IssueCToken(header, reqBody, sign)
	if err != nil {
		t.Fatalf("issue colored token fail: %v", err)
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
	if resp.CoinId != ctokenID {
		t.Fatalf("response colored token id should be %v", ctokenID)
	}
}

func TestIssueCTokenFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5015
		errMsg  = "BalancesNotSufficient"
	)

	//request body & response body
	reqBody := &structs.IssueBody{
		Issuer:  "did:axn:001",
		Owner:   "did:axn:002",
		AssetId: "asset-id-001",
		Amount:  1000,
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
		Post("/v1/transaction/tokens/issue").
		MatchHeader("X-Auth-Token", token).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do issue colored token
	resp, err := walletClient.IssueCToken(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when issue colored token fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if resp != nil {
		t.Fatalf("response object should be nil when issue colored token fail")
	}
}

func TestIssueCTokenFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5015
		errMsg  = "BalancesNotSufficient"
	)

	//request body & response body
	reqBody := &structs.IssueBody{
		Issuer:  "did:axn:001",
		Owner:   "did:axn:002",
		AssetId: "asset-id-001",
		Amount:  1000,
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
		Post("/v1/transaction/tokens/issue").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do issue colored token
	resp, err := walletClient.IssueCToken(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when issue colored token fail")
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
		t.Fatalf("response object should be nil when issue colored token fail")
	}
}

func TestIssueAssetSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token    = "user-token-001"
		ctokenID = "colored-token-id-001"
		transID  = "trans-id-001"
	)

	//request body & response body
	reqBody := &structs.IssueAssetBody{
		Issuer:  "did:axn:001",
		Owner:   "did:axn:002",
		AssetId: "asset-id-001",
	}
	sign := &structs.SignatureBody{
		Creator:        "did:axn:arxan-provider",
		Nonce:          "helloalice",
		SignatureValue: "dGhpcyBpcyBzaWduYXR1cmUgdmFsdWU=",
	}
	payload := &structs.WalletResponse{
		CoinId:         ctokenID,
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
		Post("/v1/transaction/assets/issue").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do issue digital asset
	resp, err := walletClient.IssueAsset(header, reqBody, sign)
	if err != nil {
		t.Fatalf("issue colored token fail: %v", err)
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
	if resp.CoinId != ctokenID {
		t.Fatalf("response colored token id should be %v", ctokenID)
	}
}

func TestIssueAssetFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5015
		errMsg  = "BalancesNotSufficient"
	)

	//request body & response body
	reqBody := &structs.IssueAssetBody{
		Issuer:  "did:axn:001",
		Owner:   "did:axn:002",
		AssetId: "asset-id-001",
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
		Post("/v1/transaction/assets/issue").
		MatchHeader("X-Auth-Token", token).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do issue digital asset
	resp, err := walletClient.IssueAsset(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when issue digital asset fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if resp != nil {
		t.Fatalf("response object should be nil when issue digital asset fail")
	}
}

func TestIssueAssetFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5015
		errMsg  = "BalancesNotSufficient"
	)

	//request body & response body
	reqBody := &structs.IssueAssetBody{
		Issuer:  "did:axn:001",
		Owner:   "did:axn:002",
		AssetId: "asset-id-001",
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
		Post("/v1/transaction/assets/issue").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do issue digital asset
	resp, err := walletClient.IssueAsset(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when issue digital asset fail")
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
		t.Fatalf("response object should be nil when issue digital asset fail")
	}
}

func TestTransferCTokenSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		transID = "trans-id-001"
	)

	//request body & response body
	reqBody := &structs.TransferBody{
		From:    "did:axn:001",
		To:      "did:axn:002",
		AssetId: "asset-id-001",
		Coins: []*structs.CoinAmount{
			{
				CoinId: "colored-token-id-001",
				Amount: 500,
			},
		},
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
		Post("/v1/transaction/tokens/transfer").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do transfer colored token
	resp, err := walletClient.TransferCToken(header, reqBody, sign)
	if err != nil {
		t.Fatalf("transfer colored token fail: %v", err)
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

func TestTransferCTokenFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5015
		errMsg  = "BalancesNotSufficient"
	)

	//request body & response body
	reqBody := &structs.TransferBody{
		From:    "did:axn:001",
		To:      "did:axn:002",
		AssetId: "asset-id-001",
		Coins: []*structs.CoinAmount{
			{
				CoinId: "colored-token-id-001",
				Amount: 500,
			},
		},
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
		Post("/v1/transaction/tokens/transfer").
		MatchHeader("X-Auth-Token", token).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do transfer colored token
	resp, err := walletClient.TransferCToken(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when transfer colored token fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if resp != nil {
		t.Fatalf("response object should be nil when transfer colored token fail")
	}
}

func TestTransferCTokenFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5015
		errMsg  = "BalancesNotSufficient"
	)

	//request body & response body
	reqBody := &structs.TransferBody{
		From:    "did:axn:001",
		To:      "did:axn:002",
		AssetId: "asset-id-001",
		Coins: []*structs.CoinAmount{
			{
				CoinId: "colored-token-id-001",
				Amount: 500,
			},
		},
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
		Post("/v1/transaction/tokens/transfer").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do transfer colored token
	resp, err := walletClient.TransferCToken(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when transfer colored token fail")
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
		t.Fatalf("response object should be nil when transfer colored token fail")
	}
}

func TestTransferAssetSucc(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		transID = "trans-id-001"
	)

	//request body & response body
	reqBody := &structs.TransferAssetBody{
		From:   "did:axn:001",
		To:     "did:axn:002",
		Assets: []string{"asset-id-001"},
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
		Post("/v1/transaction/assets/transfer").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	// set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do transfer asset
	resp, err := walletClient.TransferAsset(header, reqBody, sign)
	if err != nil {
		t.Fatalf("transfer asset fail: %v", err)
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

func TestTransferAssetFail(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5021
		errMsg  = "AssetNotFound"
	)

	//request body & response body
	reqBody := &structs.TransferAssetBody{
		From:   "did:axn:001",
		To:     "did:axn:002",
		Assets: []string{"asset-id-001"},
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
		Post("/v1/transaction/assets/transfer").
		MatchHeader("X-Auth-Token", token).
		Reply(errCode).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do transfer asset
	resp, err := walletClient.TransferAsset(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when transfer asset fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("err message should contains [%v]", errMsg)
	}
	if resp != nil {
		t.Fatalf("response object should be nil when transfer asset fail")
	}
}

func TestTransferAssetFailErrCode(t *testing.T) {
	//init gock & walletclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		errCode = 5021
		errMsg  = "AssetNotFound"
	)

	//request body & response body
	reqBody := &structs.TransferAssetBody{
		From:   "did:axn:001",
		To:     "did:axn:002",
		Assets: []string{"asset-id-001"},
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
		Post("/v1/transaction/assets/transfer").
		MatchHeader("X-Auth-Token", token).
		Reply(200).
		JSON(respBody)

	//set http header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	// do transfer asset
	resp, err := walletClient.TransferAsset(header, reqBody, sign)
	if err == nil {
		t.Fatalf("err should not be nil when transfer asset fail")
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
		t.Fatalf("response object should be nil when transfer asset fail")
	}
}

func TestQueryTransactionLogsSucc(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token      = "user-token-001"
		id         = structs.Identifier("did:axn:001")
		txType     = "in"
		walletAddr = "endpoint-001"
		txID01     = "tx-id-001"
		txID02     = "tx-id-002"
	)

	//build response body
	payload := structs.TransactionLogs{
		walletAddr: &structs.TransactionLog{
			Utxo: []*structs.UTXO{
				&structs.UTXO{
					SourceTxDataHash: "source-tx-data-hash",
					Ix:               1,
					CTokenId:         "ctokenid-001",
					CType:            0,
					Value:            5,
					Addr:             "endpoint-who-will-receive-this-txout",
					Until:            -1,
					Script:           []byte("payload data be attached to this tx"),
					CreatedAt: &structs.Timestamp{
						Seconds: 5555555,
						Nanos:   0,
					},
					Founder: "funder-did-0001",
					TxType:  0,
					BCTxID:  txID01,
				},
			},
			Stxo: []*structs.SpentTxOUT{
				&structs.SpentTxOUT{
					SourceTxDataHash: "source-tx-data-hash",
					Ix:               2,
					CTokenId:         "ctokenid-002",
					CType:            0,
					Value:            5,
					Addr:             "endpoint-who-will-receive-this-txout",
					Until:            -1,
					Script:           []byte("payload data be attached to this tx"),
					CreatedAt: &structs.Timestamp{
						Seconds: 6666666,
						Nanos:   0,
					},
					SpentTxDataHash: "spent-tx-data-hash",
					SpentAt: &structs.Timestamp{
						Seconds: 6666667,
						Nanos:   0,
					},
					Founder: "funder-did-0002",
					TxType:  1,
					BCTxID:  txID02,
				},
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
		Get("/v1/transaction/logs").
		MatchParam("id", string(id)).
		MatchParam("type", txType).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.QueryTransactionLogs(header, id, txType)
	if err != nil {
		t.Fatalf("get wallet info fail: %v", err)
	}
	if result == nil {
		t.Fatalf("WalletInfo object should not be nil")
	}
	if len(result) != 1 {
		t.Fatalf("response logs should contain one wallet account")
	}
	transLogs, ok := result[walletAddr]
	if !ok {
		t.Fatalf("response logs should contain the specified wallet account's trans logs: %s", walletAddr)
	}
	if transLogs == nil {
		t.Fatalf("transaction logs should not be nil when query succ")
	}
	if len(transLogs.Utxo) != 1 {
		t.Fatalf("utxo logs should contain one record")
	}
	if len(transLogs.Stxo) != 1 {
		t.Fatalf("stxo logs should contain one record")
	}
	if transLogs.Utxo[0].BCTxID != txID01 {
		t.Fatalf("utxo blockchain transaction id should be %s", txID01)
	}
	if transLogs.Stxo[0].BCTxID != txID02 {
		t.Fatalf("stxo blockchain transaction id should be %s", txID02)
	}
}

func TestQueryTransactionLogsFail(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		id      = "did:axn:001"
		txType  = "in"
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
		Get("/v1/transaction/logs").
		MatchParam("id", id).
		MatchParam("type", txType).
		Reply(errCode).
		JSON(respBody)

		//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.QueryTransactionLogs(header, id, txType)
	if err == nil {
		t.Fatalf("err should not be nil when query fail")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("error message should contains [%v]", errMsg)
	}
	if result != nil {
		t.Fatalf("TransactionLogs object should be nil when query fail")
	}
}

func TestQueryTransactionLogsFailErrCode(t *testing.T) {
	//init gock & edkeyclient
	initWalletClient(t)
	defer gock.Off()

	const (
		token   = "user-token-001"
		id      = "did:axn:001"
		txType  = "in"
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
		Get("/v1/transaction/logs").
		MatchParam("id", id).
		MatchParam("type", txType).
		Reply(200).
		JSON(respBody)

	//set header
	header := http.Header{}
	header.Set("X-Auth-Token", token)

	//do query wallet balance
	result, err := walletClient.QueryTransactionLogs(header, id, txType)
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
		t.Fatalf("TransactionLogs object should be nil when query fail")
	}
}
