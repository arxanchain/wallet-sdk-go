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
	"fmt"

	"github.com/arxanchain/sdk-go-common/crypto/sign/ed25519"
	"github.com/arxanchain/sdk-go-common/errors"
	"github.com/arxanchain/sdk-go-common/rest"
	"github.com/arxanchain/sdk-go-common/structs/did"
	"github.com/arxanchain/sdk-go-common/structs/pki"
	"github.com/arxanchain/sdk-go-common/utils"
)

func checkSignParams(signParams *pki.SignatureParam) error {
	var err error
	if signParams == nil {
		err = fmt.Errorf("request signature params invalid")
		return err
	}
	if signParams.Creator == "" {
		err = fmt.Errorf("request signature creator must be set")
		return err
	}
	if signParams.PrivateKey == "" {
		err = fmt.Errorf("request signature private key must be set")
		return err
	}
	return nil
}

func buildSignature(signParams *pki.SignatureParam, data []byte) (*pki.Signature, error) {
	var err error
	err = checkSignParams(signParams)
	if err != nil {
		return nil, err
	}

	privateKey, err := utils.DecodeBase64(signParams.PrivateKey)
	if err != nil {
		return nil, rest.CodedError(errors.SDKInvalidBase64Data, err.Error())
	}

	pri := &ed25519.PrivateKey{
		PrivateKeyData: []byte(privateKey),
	}

	sh := &pki.SignatureHeader{
		Creator: did.Identifier(signParams.Creator),
		Nonce:   []byte(signParams.Nonce),
	}

	sd := &pki.SignedData{
		Data:   data,
		Header: sh,
	}
	signData, err := sd.DoSign(pri)
	if err != nil {
		return nil, err
	}

	return signData, nil
}

func buildSignatureBody(signParams *pki.SignatureParam, data []byte) (*pki.SignatureBody, error) {
	signData, err := buildSignature(signParams, data)
	if err != nil {
		return nil, err
	}
	signBase64 := utils.EncodeBase64(signData.Sign)

	sign := &pki.SignatureBody{
		Creator:        signParams.Creator,
		Created:        signParams.Created,
		Nonce:          signParams.Nonce,
		SignatureValue: signBase64,
	}

	return sign, nil
}

// without base64 encode
func buildSignatureBodyBase(signParams *pki.SignatureParam, data []byte) (*pki.SignatureBody, error) {
	signData, err := buildSignature(signParams, data)
	if err != nil {
		return nil, err
	}

	sign := &pki.SignatureBody{
		Creator:        signParams.Creator,
		Created:        signParams.Created,
		Nonce:          signParams.Nonce,
		SignatureValue: string(signData.Sign),
	}

	return sign, nil
}
