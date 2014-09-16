/*
Promise<any> verify(AlgorithmIdentifier algorithm, Key key, CryptoOperationData signature, CryptoOperationData data);
*/
var verify = function(algorithm,key,signature,data){
	var verifypromise = new Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}

		var algo = algorithm.name;
		
		//If algorithm for sign is not in the suggested algorithms list,reject with DOMException Error
		if (verifyalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}

		if (!key.hasOwnProperty("usages")){
			reject("usages is not provided in key");
		}
		else if(key.usages.indexOf("verify")==-1){
			reject ("InvalidAccessError");
		}
		
		switch (algo){
			case "HMAC":
				//normalize the algorithm : means just check if the specified algorithm has all the specified
				//attributes in it.
				
				var hashalgo = key.algorithm.hash.name;
				//Convert back the arrayBufferView into string
				//hashing.HMAC(key,msg) => key and data are both ASCII strings.
				//key.data will be CryptoOperationData i.e. ArrayBuffer
				//data will be CryptoOperationData i.e. ArrayBuffer

				data = convertArrayBufferViewToPlainText(data);
				var keydata = convertArrayBufferViewToPlainText(key.data);
				var result;
				switch (hashalgo){
					case "SHA-1":
						hashing.hmac_hash = hashing.sha1;
						result = hashing.HMAC(keydata,data);
						break;
					case "SHA-256":
						hashing.hmac_hash = hashing.sha256;
						result = hashing.HMAC(keydata,data);
						break;	
				}
				//result is in hex and signature in CryptoOperationData
				//Convert result to string and signature to string
				result = convertHexToString(result);
				signature = convertArrayBufferViewToPlainText(signature);
				if (result == signature){
					resolve(true);
				}
				else {
					resolve(false);
				}
				break;

			case "RSASSA-PKCS1-v1_5":
				if (!key.hasOwnProperty("type")){
					reject ("Type of key is not provided");
				}
				else if (key.type != "public"){
					reject("InvalidAccessError");
				}
				else {
					data = convertArrayBufferViewToPlainText(data);
					//var privateKey = convertArrayBufferViewToPlainText(key.data);
					
					
					var publicKey;
					publicKey = convertArrayBufferViewToPlainText(key.publicKey.data);
					signature = convertStringToHex(convertArrayBufferViewToPlainText(signature));
					var result = rsa.verify_pkcs1_v1_5(data,signature,publicKey);
					resolve(result);	
				}
		}
	});
	return verifypromise;	
};
