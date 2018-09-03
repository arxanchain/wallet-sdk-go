v2.1.1 (master branch)
--------

* 注册主钱包接口
	- 请求结构中`type`字段类型由string变更为int
	- 请求结构中新增`indexes`字段，可以为新注册的钱包账户添加索引关键字
* 注册子钱包接口
	- 请求结构中`type`字段类型由string变更为int
* 钱包信息查询接口
	- 返回结构中`type`字段类型由string变更为int
	- 返回结构中`status`字段类型由string变更为int
* 创建数字资产存证接口
	- 请求结构中新增`indexes`字段，可以为新创建的数字资产存证添加索引关键字
* 查询数字资产存证接口
	- 返回结构中`status`字段类型由string变更为int
* 上传存证文件接口
	- 返回结构中新增资产存证ID
	- 返回结构中新增链外存储元数据信息
* 新增通用索引接口
	* 设置索引接口：为已经存在Did添加索引关键字
	* 查询索引接口：使用索引关键字查询Did

v2.1
--------

* 新增托管钱包私钥到平台的功能
	* 对于注册钱包的私钥，用户可以自行保存，也可以选择托管到平台上

* 数字资产存证的功能优化
	* 限制上传的数字资产存证文件大小(默认上限为10M)
	* 上传数字资产存证文件时可以指定是否只读属性，如果设置只读属性，不能再更新文件
	* 查询数字资产存证返回信息中新增文件链外存储的相关信息
	* 上传数字资产存证文件时校验文件Hash，如果平台中已经存在相同的文件，上传失败

* 修复了平台的部分Bug

v2.0.1
--------

* Add Advanced Transaction APIs to Support UTXO records signature
	* SendIssueCTokenProposal
	* SendIssueAssetProposal
	* SendTransferCTokenProposal
	* SendTransferAssetProposal
	* ProcessTx

* Simplify the API and sign only in the SDK

* Add readOnly argument to UploadPOEFile API

v2.0
--------

* Support transaction fee

	* Replace TransferBody struct with TransferCTokenBody struct

v1.5.1
--------

* Rename ColoredCoin to ColoredToken

* TransferCCoin renamed to TransferCToken

* Add UploadPOEFile API
