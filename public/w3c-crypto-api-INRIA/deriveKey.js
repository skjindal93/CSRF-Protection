var deriveKey = function(algorithm, baseKey, derivedKeyType, extractable, keyUsages){
	var deriveKeypromise = new Promise(function(resolve,reject){
		if (!algorithm.hasOwnProperty("name")){
			reject ("Name of algorithm is not provided");
		}

		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (deriveKeyalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}

		//TODO : To continue
	
	});
	return deriveKeypromise;
};