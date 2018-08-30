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
	"strconv"

	"github.com/arxanchain/sdk-go-common/errors"
	pw "github.com/arxanchain/sdk-go-common/protos/wallet"
	"github.com/arxanchain/sdk-go-common/rest"
	restapi "github.com/arxanchain/sdk-go-common/rest/api"
	rtstructs "github.com/arxanchain/sdk-go-common/rest/structs"
	"github.com/arxanchain/sdk-go-common/structs/did"
	"github.com/arxanchain/sdk-go-common/structs/pki"
	"github.com/arxanchain/sdk-go-common/structs/wallet"
)

// IssueCToken is used to issue colored token.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) IssueCToken(header http.Header, body *wallet.IssueBody, signParams *pki.SignatureParam) (result *wallet.WalletResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}

	// 1 send transfer proposal to get wallet.Tx
	issuePreRsp, err := w.SendIssueCTokenProposal(header, body, signParams)
	if err != nil {
		return nil, err
	}
	txs := issuePreRsp.Txs

	// 2 sign public key as signature
	err = w.signTxs(body.Issuer, txs, signParams)
	if err != nil {
		err = fmt.Errorf("sign Txs error: %v", err)
		return nil, err
	}

	// 3 call ProcessTx to transfer formally
	result, err = w.ProcessTx(header, txs)
	if err != nil {
		return nil, err
	}
	result.TokenId = issuePreRsp.TokenId
	return result, nil
}

// SendIssueCTokenProposal is used to send issue ctoken proposal to get wallet.Tx to be signed.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) SendIssueCTokenProposal(header http.Header, body *wallet.IssueBody, signParams *pki.SignatureParam) (issueRsp *wallet.IssueCTokenPrepareResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}
	// Build http request
	r := w.c.NewRequest("POST", "/v1/transaction/tokens/issue/prepare")
	r.SetHeaders(header)

	// Build request payload
	reqPayload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	sign, err := buildSignatureBody(signParams, reqPayload)
	if err != nil {
		return nil, err
	}

	// Build request body
	reqBody := &wallet.WalletRequest{
		Payload:   string(reqPayload),
		Signature: sign,
	}
	r.SetBody(reqBody)

	// Do http request
	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return nil, err
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return nil, err
	}

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return nil, err
	}

	issueRsp = &wallet.IssueCTokenPrepareResponse{}
	if err = json.Unmarshal([]byte(respPayload), issueRsp); err != nil {
		return nil, err
	}
	return issueRsp, nil
}

// IssueAsset is used to issue digital asset.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) IssueAsset(header http.Header, body *wallet.IssueAssetBody, signParams *pki.SignatureParam) (result *wallet.WalletResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}

	// 1 send proposal to get wallet.Tx
	txs, err := w.SendIssueAssetProposal(header, body, signParams)
	if err != nil {
		return nil, err
	}

	// 2 sign public key as signature
	err = w.signTxs(body.Issuer, txs, signParams)
	if err != nil {
		err = fmt.Errorf("sign Txs error: %v", err)
		return nil, err
	}

	// 3 call ProcessTx to transfer formally
	return w.ProcessTx(header, txs)
}

// TransferCToken is used to transfer colored tokens from one user to another.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) TransferCToken(header http.Header, body *wallet.TransferCTokenBody, signParams *pki.SignatureParam) (result *wallet.WalletResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}

	// 1 send transfer proposal to get wallet.Tx
	txs, err := w.SendTransferCTokenProposal(header, body, signParams)
	if err != nil {
		return nil, err
	}

	// 2 sign public key as signature
	err = w.signTxs(body.From, txs, signParams)
	if err != nil {
		err = fmt.Errorf("sign Txs error: %v", err)
		return nil, err
	}

	// 3 call ProcessTx to transfer formally
	return w.ProcessTx(header, txs)
}

// TransferAsset is used to transfer assets from one user to another.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) TransferAsset(header http.Header, body *wallet.TransferAssetBody, signParams *pki.SignatureParam) (result *wallet.WalletResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}

	// 1 send transfer proposal to get wallet.Tx
	txs, err := w.SendTransferAssetProposal(header, body, signParams)
	if err != nil {
		return nil, err
	}

	// 2 sign public key as signature
	err = w.signTxs(body.From, txs, signParams)
	if err != nil {
		err = fmt.Errorf("sign Txs error: %v", err)
		return nil, err
	}

	// 3 call ProcessTx to transfer formally
	return w.ProcessTx(header, txs)
}

// SendIssueAssetProposal is used to send issue asset proposal to get wallet.Tx to be signed.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) SendIssueAssetProposal(header http.Header, body *wallet.IssueAssetBody, signParams *pki.SignatureParam) (result []*pw.TX, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/transaction/assets/issue/prepare")
	r.SetHeaders(header)

	// Build request payload
	reqPayload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	sign, err := buildSignatureBody(signParams, reqPayload)
	if err != nil {
		return nil, err
	}

	// Build request body
	reqBody := &wallet.WalletRequest{
		Payload:   string(reqPayload),
		Signature: sign,
	}
	r.SetBody(reqBody)

	// Do http request
	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return nil, err
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return nil, err
	}

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return nil, err
	}
	err = json.Unmarshal([]byte(respPayload), &result)
	if err != nil {
		return nil, err
	}
	return result, err
}

// SendTransferCTokenProposal is used to send transfer colored tokens proposal to get wallet.Tx to be signed.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) SendTransferCTokenProposal(header http.Header, body *wallet.TransferCTokenBody, signParams *pki.SignatureParam) (result []*pw.TX, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/transaction/tokens/transfer/prepare")
	r.SetHeaders(header)

	// Build request payload
	reqPayload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	sign, err := buildSignatureBody(signParams, reqPayload)
	if err != nil {
		return nil, err
	}

	// Build request body
	reqBody := &wallet.WalletRequest{
		Payload:   string(reqPayload),
		Signature: sign,
	}
	r.SetBody(reqBody)

	// Do http request
	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return nil, err
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return nil, err
	}

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return nil, err
	}
	err = json.Unmarshal([]byte(respPayload), &result)
	if err != nil {
		return nil, err
	}
	return result, err
}

// SendTransferAssetProposal is used to send transfer asset proposal to get wallet.Tx to be signed.
//
// The default invoking mode is asynchronous, it will return
// without waiting for blockchain transaction confirmation.
//
// If you want to switch to synchronous invoking mode, set
// 'BC-Invoke-Mode' header to 'sync' value. In synchronous mode,
// it will not return until the blockchain transaction is confirmed.
//
// The default key pair trust mode does not trust, it will required key pair.
// If you had trust the key pair, it will required security code.
//
func (w *WalletClient) SendTransferAssetProposal(header http.Header, body *wallet.TransferAssetBody, signParams *pki.SignatureParam) (result []*pw.TX, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	if w.s != nil {
		signParams, err = w.queryPrivateKey(header, signParams)
		if err != nil {
			return
		}
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/transaction/assets/transfer/prepare")
	r.SetHeaders(header)

	// Build request payload
	reqPayload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	sign, err := buildSignatureBody(signParams, reqPayload)
	if err != nil {
		return nil, err
	}

	// Build request body
	reqBody := &wallet.WalletRequest{
		Payload:   string(reqPayload),
		Signature: sign,
	}
	r.SetBody(reqBody)

	// Do http request
	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return nil, err
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return nil, err
	}

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return nil, err
	}
	err = json.Unmarshal([]byte(respPayload), &result)
	if err != nil {
		return nil, err
	}
	return result, err
}

func (w *WalletClient) signTxs(founder string, txs []*pw.TX, signParams *pki.SignatureParam) (err error) {
	for _, tx := range txs {
		if tx.Founder != founder {
			// sign fee by platform private key
			platformSignParams, err := w.c.GetEnterpriseSignParam()
			if err != nil {
				return err
			}

			w.signTx(tx, platformSignParams)
		} else {
			w.signTx(tx, signParams)
		}
	}
	return nil
}

func (w *WalletClient) signTx(tx *pw.TX, signParams *pki.SignatureParam) (err error) {
	for _, txout := range tx.Txout {
		if txout.Script == nil {
			err = fmt.Errorf("script is nil, no need to sign")
			return err
		}
		utxoSignature := &pw.UTXOSignature{}
		err = json.Unmarshal(txout.Script, utxoSignature)
		if err != nil {
			err = fmt.Errorf("Unmarshal script error: %v", err)
			return err
		}
		if utxoSignature.PublicKey == nil {
			continue
		}
		signatureBody, err := buildSignatureBodyBase(signParams, utxoSignature.PublicKey)
		if err != nil {
			err = fmt.Errorf("sign error: %v", err)
			return err
		}
		utxoSignature.Signature = []byte(signatureBody.SignatureValue)
		utxoSignature.Nonce = signParams.Nonce
		utxoSignature.Creator = string(signParams.Creator)
		signData, err := json.Marshal(utxoSignature)
		if err != nil {
			return err
		}
		txout.Script = signData
	}
	return nil
}

// ProcessTx is used to transfer formally with signature TX
func (w *WalletClient) ProcessTx(header http.Header, txs []*pw.TX) (result *wallet.WalletResponse, err error) {

	if txs == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v1/transaction/process")
	r.SetHeaders(header)

	// Build request payload
	txBody := &wallet.ProcessTxBody{
		Txs: txs,
	}
	r.SetBody(txBody)

	// Do http request
	_, resp, err := restapi.RequireOK(w.c.DoRequest(r))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse http response
	var respBody rtstructs.Response
	if err = restapi.DecodeBody(resp, &respBody); err != nil {
		return nil, err
	}

	if respBody.ErrCode != errors.SuccCode {
		err = rest.CodedError(respBody.ErrCode, respBody.ErrMessage)
		return nil, err
	}

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return nil, err
	}
	err = json.Unmarshal([]byte(respPayload), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// QueryTransactionLogs is used to query transaction logs.
//
// txType:
// in: query income type transaction
// out: query spending type transaction
// other: in && out
// num, page: count and page to be returned
//
func (w *WalletClient) QueryTransactionLogs(header http.Header, id did.Identifier, txType string, num, page int32) (result []*pw.UTXO, err error) {
	fmt.Printf("*****in wallet-sdk-go id: %v, txType: %v, num: %v, page: %v\n", id, txType, num, page)
	if id == "" {
		err = fmt.Errorf("request id invalid")
		return
	}
	if num < 0 {
		num = 0
	}
	if page <= 0 {
		page = 1
	}

	numStr := strconv.Itoa(int(num))
	pageStr := strconv.Itoa(int(page))
	// Build http request
	r := w.c.NewRequest("GET", "/v1/transaction/logs")
	r.SetHeaders(header)
	r.SetParam("id", string(id))
	r.SetParam("type", txType)
	r.SetParam("num", numStr)
	r.SetParam("page", pageStr)

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

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(respPayload), &result)

	return
}

// QueryTransactionUTXO is used to query transaction UTXO logs.
//
// num, page: count and page to be returned
//
func (w *WalletClient) QueryTransactionUTXO(header http.Header, id did.Identifier, num, page int32) (result []*pw.UTXO, err error) {
	if id == "" {
		err = fmt.Errorf("request id invalid")
		return
	}
	if num < 0 {
		num = 0
	}
	if page <= 0 {
		page = 1
	}

	numStr := strconv.Itoa(int(num))
	pageStr := strconv.Itoa(int(page))
	// Build http request
	r := w.c.NewRequest("GET", "/v1/transaction/utxo")
	r.SetHeaders(header)
	r.SetParam("id", string(id))
	r.SetParam("num", numStr)
	r.SetParam("page", pageStr)

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

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(respPayload), &result)

	return
}

// QueryTransactionSTXO is used to query transaction UTXO logs.
//
// num, page: count and page to be returned
//
func (w *WalletClient) QueryTransactionSTXO(header http.Header, id did.Identifier, num, page int32) (result []*pw.UTXO, err error) {
	if id == "" {
		err = fmt.Errorf("request id invalid")
		return
	}
	if num < 0 {
		num = 0
	}
	if page <= 0 {
		page = 1
	}

	numStr := strconv.Itoa(int(num))
	pageStr := strconv.Itoa(int(page))
	// Build http request
	r := w.c.NewRequest("GET", "/v1/transaction/stxo")
	r.SetHeaders(header)
	r.SetParam("id", string(id))
	r.SetParam("num", numStr)
	r.SetParam("page", pageStr)

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

	respPayload, ok := respBody.Payload.(string)
	if !ok {
		err = fmt.Errorf("response payload type invalid: %v", reflect.TypeOf(respBody.Payload))
		return
	}

	err = json.Unmarshal([]byte(respPayload), &result)

	return
}
