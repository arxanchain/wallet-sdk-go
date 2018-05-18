# Status
[![Build Status](https://travis-ci.org/arxanchain/wallet-sdk-go.svg?branch=master)](https://travis-ci.org/arxanchain/wallet-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/arxanchain/wallet-sdk-go)](https://goreportcard.com/report/github.com/arxanchain/wallet-sdk-go)
[![GoDoc](https://godoc.org/github.com/arxanchain/wallet-sdk-go?status.svg)](https://godoc.org/github.com/arxanchain/wallet-sdk-go)

# wallet-go-sdk

Blockchain Wallet SDK includes APIs for managing wallet accounts (DID),
digital assets (POE), colored tokens etc.

You need not care about how the backend blockchain runs or the unintelligible
techniques, such as consensus, endorsement and decentralization. Simply use
the SDK we provide to implement your business logics, we will handle caching,
tagging, compressing, encrypting and high availability.

Please refer to the API document: [Blockchain wallet platform](http://www.arxanfintech.com/infocenter/html/development/wallet.html)

# Usage

## Install

Run the following command to download the Go SDK:

```code
go get github.com/arxanchain/wallet-sdk-go/api
```

## New wallet client

To invoke the SDK API, you first need to create a wallet client as follows:

```code
// Create wallet client
config := &restapi.Config{
	Address:    "http://172.16.13.6:9143",
	ApiKey:     "pWEzB4yMM1518346407",
	CryptoCfg: &restapi.CryptoConfig{
		Enable:         true,
		CertsStorePath: "/path/to/client/certs",
	},
	EnterpriseSignParam: &restapi.EnterpriseSignParam{
		Creator: "did:axn:09e2fc68-f51e-4aff-b6e4-427cce3ed1af",
		Nonce: "nonce",
		PrivateKey: "RiQ+oEuaelf2aecUZvG7xrWr+p43ZfjGZYfDCXfQD+ku0xY5BXP8kIKhiqzKRvfyKBKM3y7V9O1bF7X3M9mxkQ==",
	},
}
walletClient, err := walletapi.NewWalletClient(config)
if err != nil {
	fmt.Printf("New wallet client fail: %v\n", err)
	return
}
fmt.Printf("New wallet client succ\n")
```

* When building the client configuration, the **Address** and **ApiKey** fields must
be set. The **Address** is set to the http address of wallet-ng service, and the
**ApiKey** is set to the API access key obtained on `ChainConsole` management page.

* If you invoke the APIs via `wasabi` service, the **Address** field should
be set to the http address of `wasabi` service, and the **CryptoCfg** field must be
set with **CryptoCfg.Enable** being `true` and **Cryptocfg.CertsStorePath** being the
path to client certificates (contains the platform public cert and user private key).

* `wasabi` service is ArxanChain BaaS API gateway with token authentication, data
encryption, and verifying signature.  For security requirement, enable crypto is
recommended for production environment.

* Enterprisesignparam: Enterprise signature parameter, used to sign UTXO records for AXT fee.
	- Creator: Enterprise wallet did
	- Nonce: Signature random nonce string
	- PrivateKey: The ed25519 private key of enterprise wallet

About how to apply API-Key, please refer to [Apikey Application](http://www.arxanfintech.com/infocenter/html/baas/enterprise/v1.2/api-access.html#api-access-ref)

## Register wallet account

After creating wallet client, you can use this client to register wallet account
as follows:

```code
// Build request header
header := http.Header{}
// If you use synchronous invoking mode, set following header
header.Set("Bc-Invoke-Mode", "sync")
// If you use asynchronous invoking mode, set following header
// header.Set("Callback-Url", "http://callback-url")

// Register wallet account
registerBody := &structs.RegisterWalletBody{
	Type:   "Organization",
	Access: "alice0001",
	Secret: "Alice#123456",
}
resp, err = walletClient.Register(header, registerBody)
if err != nil {
	fmt.Printf("Register wallet fail: %v\n", err)
	return
}
walletID := resp.Id
keyPair := resp.KeyPair
fmt.Printf("Register wallet succ.\nwallet id: %v\nED25519 public key: %v\nED25519 private key: %v", walletID, keyPair.PublicKey, keyPair.PrivateKey)
```

* `Callback-Url` in the http header is optional. You only need to set it
if you need to receive blockchain transaction events.

* If you want to switch to synchronous invoking mode, set 'BC-Invoke-Mode'
header to 'sync' value. In synchronous mode, it will not return until the
blockchain transaction is confirmed.

## Create POE digital asset and upload file

After creating the wallet account, you can create POE assets for this account as follows:

```code
// Create poe asset
poeBody := &structs.POEBody{
	Name:     "TestPOE",
	Owner:    walletID,
	Metadata: []byte("poe metadata"),
}
signParam := &structs.SignatureParam{
	Creator:    walletID,
	Nonce:      "nonce",
	PrivateKey: keyPair.PrivateKey,
}
resp, err = walletClient.CreatePOE(header, poeBody, signParam)
if err != nil {
	fmt.Printf("CreatePOE fail: %v\n", err)
	return
}
fmt.Printf("Create POE succ. Response: %+v\n", resp)

// Upload poe file
poeID := string(resp.Id)
poeFile := "./test-upload-file"
resp, err = walletClient.UploadPOEFile(header, poeID, poeFile)
if err != nil {
	fmt.Printf("UploadPOEFail fail: %v\n", err)
	return
}
fmt.Printf("Upload POE file succ. Response: %+v\n", resp)
```

* When creating POE assets, the **Name** and **Owner** fields must be set, and the
**Owner** field must be set to the wallet account ID.

* When building the signature parameter, use the ed25519 private key returned
when registering wallet to do ed25519 signing.

* `UploadPOEFile` API uploads the file to **Offchain** storage, generates SHA256
hash value for this file, and saves this hash value into blockchain.

## Issue colored token using digital asset

Once you have possessed assets, you can use a specific asset to issue colored
token as follows:

```code
// Issue colored token
issueBody := &structs.IssueBody{
	Issuer:  string(issuerID),
	Owner:   string(walletID),
	AssetId: string(poeID),
	Amount:  1000,
}
signParam = &structs.SignatureParam{
	Creator:    walletID,
	Nonce:      "nonce",
	PrivateKey: keyPair.PrivateKey,
}
resp, err = walletClient.IssueCToken(header, issueBody, signParam)
if err != nil {
	fmt.Printf("Issue colored token fail: %v\n", err)
	return
}
fmt.Printf("Issue colored token succ. Response: %+v\n", resp)
```

* When issuing colored token, you need to specify an issuer (one wallet account ID),
an asset to issue token, and the asset owner (another wallet account ID).

## Transfer colored token

After issuing colored token, the asset owner's wallet account will own these
colored tokens, and can transfer some of them to other wallet accounts.

```code
// Transfer colored token
transferBody := &structs.TransferCTokenBody{
	From: string(walletID),
	To:   string(toID),
	Tokens: []*structs.TokenAmount{
		&structs.TokenAmount{
			TokenId: tokenId,
			Amount:  100,
		},
	},
}
signParam = &structs.SignatureParam{
	Creator:    walletID,
	Nonce:      "nonce",
	PrivateKey: keyPair.PrivateKey,
}
resp, err = walletClient.TransferCToken(header, transferBody, signParam)
if err != nil {
	fmt.Printf("Transfer colored token fail: %v\n", err)
	return
}
fmt.Printf("Transfer colored token succ. Response: %+v\n", resp)
```

## Query colored token balance

You can use the `GetWalletBalance` API to get the balance of the specified wallet
account as follows:

```code
// Query wallet balance
balance, err = walletClient.GetWalletBalance(header, walletID)
if err != nil {
	fmt.Printf("Get wallet(%s) balance fail: %v\n", walletID, err)
	return
}
if balance.ColoredTokens != nil {
	fmt.Printf("Get wallet(%s) colored tokens succ\n", walletID)
	for ctokenId, ctoken := range balance.ColoredTokens {
		fmt.Printf("===> CTokenID: %v, Amount: %v\n", ctokenId, ctoken.Amount)
	}
}
if balance.DigitalAssets != nil {
	fmt.Printf("Get wallet(%s) digital assets succ\n", walletID)
	for assetId, asset := range balance.DigitalAssets {
		fmt.Printf("===> AssetID: %v, Amount: %v\n", assetId, asset.Amount)
	}
}
```

## How to do ed25519 signing?

For the APIs that USES the ED25519 signature, we usually provide two forms:
*APIName* and *APIName*Sign.

The APIs with the `Sign` suffix accept user ED25519 private key, and do the ED25519
signing inside SDK.

The APIs without the `Sign` suffix directly accept the signed value that the user
has already done. This section will walk you through how to do ED25519 signing by yourself.

```code
privateKey, err := utils.DecodeBase64(base64PrivateKey)
if err != nil {
	fmt.Printf("DecodeBase64 private key fail: %v\n", err)
	return
}

pri := &ed25519.PrivateKey{
	PrivateKeyData: []byte(privateKey),
}

sh := &structs.SignatureHeader{
	Creator: structs.Identifier(walletID),
	Nonce:   []byte("nonce"),
}

sd := &structs.SignedData{
	Data:   data,
	Header: sh,
}
signData, err := sd.DoSign(pri)
if err != nil {
	fmt.Printf("DoSign fail: %v\n", err)
	return
}
signBase64 := utils.EncodeBase64(signData.Sign)

signBody := &structs.SignatureBody{
	Creator:        walletID,
	Created:        created,
	Nonce:          "nonce",
	SignatureValue: signBase64,
}
```

Before doing ED25519 signing, you should import [ed25519](github.com/arxanchain/sdk-go-common/crypto/sign/ed25519) package.

## Using callback URL to receive blockchain transaction events

Each of the APIs for invoking blockchain has two invoking modes, one is `sync`
mode, the other is `async` mode.

The default invoking mode is asynchronous, it will return without waiting for
blockchain transaction confirmation. In asynchronous mode, you should set
`Callback-Url` in the http header to receive blockchain transaction events.

The blockchain transaction event structure is defined as follows:

```code
import google_protobuf "github.com/golang/protobuf/ptypes/timestamp

// Blockchain transaction event payload
type BcTxEventPayload struct {
	BlockNumber   uint64                     `json:"block_number"`   // Block number
	BlockHash     []byte                     `json:"block_hash"`     // Block hash
	ChannelId     string                     `json:"channel_id"`     // Channel ID
	ChaincodeId   string                     `json:"chaincode_id"`   // Chaincode ID
	TransactionId string                     `json:"transaction_id"` // Transaction ID
	Timestamp     *google_protobuf.Timestamp `json:"timestamp"`      // Transaction timestamp
	IsInvalid     bool                       `json:"is_invalid"`     // Is transaction invalid
	Payload       interface{}                `json:"payload"`        // Transaction Payload
}
```

One blockchain transaction event sample as follows:

```code
{
	"block_number":63,
	"block_hash":"vTRmfHZ3aaecbbw2A5zPcuzekUC42Lid3w+i6dOU5C0=",
	"channel_id":"pubchain",
	"chaincode_id":"pubchain-c4:",
	"transaction_id":"243eaa6e695cc4ce736e765395a64b8b917ff13a6c6500a11558b5e94e02556a",
	"timestamp":{
		"seconds":1521189855,
		"nanos":192203115
	},
	"is_invalid":false,
	"payload":{
		"id":"4debe20b-ca00-49b0-9130-026a1aefcf2d",
		"metadata":{
			"member_id_value":"3714811988020512",
			"member_mobile":"6666",
			"member_name":"8777896121269017",
			"member_truename":"Tony"
		}
	}
}
```

If you want to switch to synchronous invoking mode, set `Bc-Invoke-Mode` header
to `sync` value. In synchronous mode, it will not return until the blockchain
transaction is confirmed.
