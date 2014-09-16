var wrapKey = function(format, key, wrappingKey, wrapAlgorithm){
	var wrapKeypromise = new Promise(function(resolve,reject){
		var algorithm = wrapAlgorithm;
		
		if (!algorithm.hasOwnProperty("name")){
			reject ("Name of algorithm is not provided");
		}

		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (wrapKeyalgos.indexOf(algo)==-1 && encryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}
		//Checking if the format is one of the recognized key format values
		if (!checkRecognizedKeyFormatValues(format)){
			reject ("SyntaxError");
		}

		if (!wrappingKey.hasOwnProperty("usages")){
			reject("usages attribute of wrapping key not specified");
		}
		else if (wrappingKey.usages.indexOf("wrapKey")==-1){
			reject("InvalidAccessError");
		}

		if (!key.hasOwnProperty("algorithm")){
			reject ("algorithm in key is not provided");
		}
		else if (!key.algorithm.hasOwnProperty("name")){
			reject("name of key algorithm not provided");
		}
		else if (exportKeyalgos.indexOf(key.algorithm.name)==-1){
			reject("NotSupportedError");
		}

		if (!key.hasOwnProperty("extractable")){
			reject ("extractable attribute of key not specified");
		}
		else if (!key.extractable){
			reject("InvalidAccessError");
		}


		var bytes;
		crypto.subtle.exportKey(format,key).then(function(r){
				bytes = r;
		});

		//TODO : Wrap the key;
		var result;
		crypto.subtle.encrypt(algorithm,wrappingKey,bytes).then(function(r){
				result = r;
				resolve(result);
		});

	});
	return wrapKeypromise;
};