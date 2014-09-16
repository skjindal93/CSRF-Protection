/*
	Promise<any> digest(AlgorithmIdentifier algorithm, CryptoOperationData data);
*/
var digest = function(algorithm,data){
	var digestpromise = new Promise(function(resolve,reject){
		if (!algorithm){
			reject("algorithm should not be null");
		}
		if (!algorithm.hasOwnProperty("name")){
			reject ("Name of algorithm is not provided");
		}

		if (!data){
			reject("Data should not be null");
		}

		if (typeof(data)!="object"){

			reject("Data should be object");
		}

		var algo = algorithm.name;
		//Checking if the algo name in present in the suggested algorithms
		if (digestalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}
		var result;
		data = convertArrayBufferViewToPlainText(data);
		
		switch (algo){
			case "SHA-1":
				result = hashing.SHA1(data);
				result = convertHexToString(result);
				result = convertPlainTextToArrayBufferView(result);
				break;
			case "SHA-256":
				result = hashing.SHA256(data);

				result = convertHexToString(result);
				result = convertPlainTextToArrayBufferView(result);
				break;
		}

		resolve(result);
	});
	return digestpromise;	
};