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

/////////////////////////////////////////////////////////////////////////////////////////////////
// Issue Colored Token

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
	issuePreRsp, err := w.SendIssueCTokenProposal(header, body)
	if err != nil {
		return nil, err
	}
	txs := issuePreRsp.Txs

	// 2 sign public key as signature
	err = w.SignTxs(txs, signParams)
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
func (w *WalletClient) SendIssueCTokenProposal(header http.Header, body *wallet.IssueBody) (issueRsp *wallet.IssueCTokenPrepareResponse, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v2/transaction/tokens/issue/prepare")
	r.SetHeaders(header)
	r.SetBody(body)

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

/////////////////////////////////////////////////////////////////////////////////////////////////
// Issue Asset

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
	txs, err := w.SendIssueAssetProposal(header, body)
	if err != nil {
		return nil, err
	}

	// 2 sign public key as signature
	err = w.SignTxs(txs, signParams)
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
func (w *WalletClient) SendIssueAssetProposal(header http.Header, body *wallet.IssueAssetBody) (result []*pw.TX, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v2/transaction/assets/issue/prepare")
	r.SetHeaders(header)
	r.SetBody(body)

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

/////////////////////////////////////////////////////////////////////////////////////////////////
// Transfer Colored Token

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
	txs, err := w.SendTransferCTokenProposal(header, body)
	if err != nil {
		return nil, err
	}

	// 2 sign public key as signature
	err = w.SignTxs(txs, signParams)
	if err != nil {
		err = fmt.Errorf("sign Txs error: %v", err)
		return nil, err
	}

	// 3 call ProcessTx to transfer formally
	return w.ProcessTx(header, txs)
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
func (w *WalletClient) SendTransferCTokenProposal(header http.Header, body *wallet.TransferCTokenBody) (result []*pw.TX, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v2/transaction/tokens/transfer/prepare")
	r.SetHeaders(header)
	r.SetBody(body)

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

/////////////////////////////////////////////////////////////////////////////////////////////////
// Transfer Asset

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
	txs, err := w.SendTransferAssetProposal(header, body)
	if err != nil {
		return nil, err
	}

	// 2 sign public key as signature
	err = w.SignTxs(txs, signParams)
	if err != nil {
		err = fmt.Errorf("sign Txs error: %v", err)
		return nil, err
	}

	// 3 call ProcessTx to transfer formally
	return w.ProcessTx(header, txs)
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
func (w *WalletClient) SendTransferAssetProposal(header http.Header, body *wallet.TransferAssetBody) (result []*pw.TX, err error) {
	if body == nil {
		err = fmt.Errorf("request payload invalid")
		return nil, err
	}

	// Build http request
	r := w.c.NewRequest("POST", "/v2/transaction/assets/transfer/prepare")
	r.SetHeaders(header)
	r.SetBody(body)

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

// SignTxs is used to sign multiple UTXOs
// using the given private key in signParams
// param txs: transactions to be signed
// param signParams: private key userd for signature
// return: err not nil if failed
func (w *WalletClient) SignTxs(txs []*pw.TX, signParams *pki.SignatureParam) (err error) {
	signCreator := string(signParams.Creator)
	for _, tx := range txs {
		if tx.Founder != signCreator {
			// sign fee by platform private key
			platformSignParams, err := w.c.GetEnterpriseSignParam()
			if err != nil {
				return err
			}

			w.SignTx(tx, platformSignParams)
		} else {
			w.SignTx(tx, signParams)
		}
	}
	return nil
}

// SignTx is used to sign single UTXO
//
func (w *WalletClient) SignTx(tx *pw.TX, signParams *pki.SignatureParam) (err error) {
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
	r := w.c.NewRequest("POST", "/v2/transaction/process")
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
	r := w.c.NewRequest("GET", "/v2/transaction/logs")
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
	r := w.c.NewRequest("GET", "/v2/transaction/utxo")
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
	r := w.c.NewRequest("GET", "/v2/transaction/stxo")
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
