var unwrapKey = function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages){
	var unwrapKeypromise = new Promise(function(resolve,reject){
		var algorithm = unwrapAlgorithm;
		
		if (!algorithm.hasOwnProperty("name")){
			reject ("Name of algorithm is not provided");
		}

		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (unwrapKeyalgos.indexOf(algo)==-1 && decryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}

		if (!unwrappedKeyAlgorithm.hasOwnProperty("name")){
			reject ("Name of the unwrap key algorithm is not provided");
		}

		if (importKeyalgos.indexOf(unwrappedKeyAlgorithm.name)==-1){
			reject("NotSupportedError");
		}

		if (!unwrappingKey.hasOwnProperty("usages")){
			reject ("usages attribute of unwrappingKey is not provided");
		}
		else if (unwrappingKey.usages.indexOf("unwrapKey")==-1){
			reject ("InvalidAccessError");
		}
		//Checking if the format is one of the recognized key format values
		if (!checkRecognizedKeyFormatValues(format)){
			reject ("SyntaxError");
		}

		if (!checkRecognizedKeyUsageValues(keyUsages)){
			reject("SyntaxError");
		}

		//TODO : How to unwrap the key
		var bytes;
		crypto.subtle.decrypt(unwrapAlgorithm,unwrappingKey,wrappedKey).then(function(r){
				bytes = r;	
		});
		var result;
		crypto.subtle.importKey(format,bytes,unwrappedKeyAlgorithm,extractable,keyUsages).then(function(r){
				result = r;
				resolve(result);
		});
	});
	return unwrapKeypromise;
};