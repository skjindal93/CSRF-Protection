/* 
Promise<any> sign(AlgorithmIdentifier algorithm, Key key, CryptoOperationData data);
*/

var sign = function(algorithm,key,data){
	var signpromise = new Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}
		var algo = algorithm.name;
		//If algorithm for sign is not in the suggested algorithms list,reject with DOMException Error
		if (signalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}

		if (!key.hasOwnProperty("usages")){
			reject("usages is not provided in key");
		}					
		else if(key.usages.indexOf("sign")==-1){
			reject ("InvalidAccessError");
		}

		switch (algo){
			case "HMAC":
				//normalize the algorithm : means just check if the specified algorithm has all the specified
				//attributes in it.
				
				//TODO : Check all the key attributes
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
					
				result = convertHexToString(result);
				result = convertPlainTextToArrayBufferView(result);
				resolve(result);

				break;

			case "RSASSA-PKCS1-v1_5":
				if (!key.hasOwnProperty("type")){
					reject ("Type of key is not provided");
				}
				else if (key.type != "private"){
					reject("InvalidAccessError");
				}
				else {
					data = convertArrayBufferViewToPlainText(data);
					var privateKey = convertArrayBufferViewToPlainText(key.data);
					var result = rsa.sign_pkcs1_v1_5(data,privateKey);
					resolve(result);	
				}
				break;
		}	
	});
return signpromise;
};