/*
	Promise<any> importKey(KeyFormat format, CryptoOperationData keyData, AlgorithmIdentifier? algorithm, 
							boolean extractable, KeyUsage[] keyUsages );
*/

var importKey = function(format,keyData,algorithm,extractable,keyUsages){

	var importKeypromise = new Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}

		if (!keyData){
			reject("keyData is null");
		}


		var algo = algorithm.name;
		
		//Checking if the algo name in present in the suggested algorithms
		if (importKeyalgos.indexOf(algo)==-1){

			//Not correct. Check how to reject a DOMException
			reject("The algorithm is not supported");
		}
			
		//Checking if the format is one of the recognized key format values
		if (!checkRecognizedKeyFormatValues(format)){
			reject ("SyntaxError");
		}

		//Checking if the any of the value of keyUsages are in the Recognized Key Usage Values
		if (!checkRecognizedKeyUsageValues(keyUsages)){
			reject ("InvalidAccessError");
		}

		switch(algo){
			case "HMAC":

				//If usages contains an entry which is not "sign" or "verify", then return an error named DataError.
				if (keyUsages.indexOf("sign")==-1 && keyUsages.indexOf("verify")==-1){
					reject ("DataError");
				}

				var name;
				
				//Checking format
				switch(format){
					case "raw":
						
						//Not sure what is octet string.
						//TODO: Converting the keyData into normal String by convertArrayBufferViewToPlainText
						
						
						/*if (keyData.length==0){
							reject ("DataError");
						}*/


						if (algorithm.hasOwnProperty("hash") && algorithm.hash.hasOwnProperty("name")){
							name = algorithm.hash.name;
						}
						else {
							reject("SyntaxError");
						}

						break;
				}
				var data = convertArrayBufferViewToPlainText(keyData);
				//hash is the new KeyAlgorithm
				var hash = {
					name : name
				};
				var HmacKeyAlgorithm = {
					name : "HMAC",
					hash : hash
				};
				var key = {
					type : "secret",
					extractable : extractable,
					algorithm : HmacKeyAlgorithm,
					
					//TODO: intersection of keyUsages and recognizedKeyUsageValues
					usages : keyUsages, 
					data : keyData
				};
				resolve(key);
				break;

			case "AES-CBC":


				var length;
				if (keyUsages.indexOf("encrypt")==-1 && keyUsages.indexOf("decrypt")==-1 && keyUsages.indexOf("wrapKey")==-1 && keyUsages.indexOf("unwrapKey")==-1){
					reject ("DataError");
				}

				switch(format){
					case "raw":
						//Not sure what is octet string.
						//TODO: Converting the keyData into normal String by convertArrayBufferViewToPlainText
						
						var checklength = keyData.length*8;
						
						if (checklength!=128 && checklength!=192 && checklength!=256){
							reject ("DataError");
						}
						else {
							length = checklength;
						}
						break;
				}

				var data = convertArrayBufferViewToPlainText(keyData);

				var AesKeyAlgorithm = {
					name : "AES-CBC",
					length : length
				};

				var key = {
					type : "secret",
					extractable : extractable,
					algorithm : AesKeyAlgorithm,
					//TODO: intersection of keyUsages and recognizedKeyUsageValues
					usages : keyUsages, 
					data : keyData
				};

				resolve(key);
				break;
			
			case "RSA-OAEP":
			case "RSASSA-PKCS1-v1_5":
			
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}
				var hash;
				var key;

				var publicKey,privateKey;

				if (!algorithm.hash.hasOwnProperty("name")){
					reject ("DataError");
				}
			
				switch(format){
					case "spki":
						//TODO : What is all the stuff about parsing?
						keyData = convertStringToHex(convertArrayBufferViewToPlainText(keyData));

						publicKey = convert(keyData,'auto');
						
						if (publicKey.length!=3){
							reject("DataError");
						}

						var alg = publicKey[0];
						if (alg == "1.2.840.113549.1.1.1"){

						}

						//TODO : id-RSAES-OAEP
						if (hash){

						}
						else {
							hash = algorithm.hash.name;	
						}

						publicKey = convert(publicKey[2],'auto');
						
						if (publicKey.length!=2){
							reject("DataError");
						}

						publicKey.n = publicKey[0];
						publicKey.e = publicKey[1];

						key = {
							type : "public",
							extractable : extractable,
							usages : keyUsages,
							data : publicKey,
						};

						break;

					case "pkcs8":

						keyData = convertStringToHex(convertArrayBufferViewToPlainText(keyData));
						privateKey = convert(keyData,'auto');
						if (privateKey.length!=4){
							reject("DataError");
						}

						var alg = privateKey[0];
						if (alg == "1.2.840.113549.1.1.1"){

						}

						//TODO : id-RSAES-OAEP
						if (hash){

						}
						else {
							hash = algorithm.hash.name;	
						}

						var privateKey = convert(privateKey[2],'auto');
						if (privateKey.length!=9){
							reject("DataError");
						}

						privateKey.version = privateKey[0];
						privateKey.n = privateKey[1];
						privateKey.e = privateKey[2];
						privateKey.d = privateKey[3];
						privateKey.p = privateKey[4];
						privateKey.q = privateKey[5];
						privateKey.dmp1 = privateKey[6];
						privateKey.dmq1 = privateKey[7];
						privateKey.iqmp = privateKey[8];

						key = {
							type : "private",
							extractable : extractable,
							usages : keyUsages,
							data : privateKey,
						};

						break;

					case "jwk":
						if (keyData.hasOwnProperty('d')){
							type = "private";
						}
						else {
							if (!keyData.hasOwnProperty('n') || !keyData.hasOwnProperty('e')){
								reject("Public Key not valid");
							}
							type = "public";
						}
						break;

					default:
						reject("NotSupportedError");
				}

				var keyAlgorithm = {
					name : hash
				};
				console.log();

				var RsaHashedKeyAlgorithm = {
					name : "RSA-OAEP",
					modulusLength : publicKey.n.length,
					publicExponent : publicKey.e,
					hash : keyAlgorithm
				};

				key.algorithm = RsaHashedKeyAlgorithm;

				resolve(key);

				break;
			

			default:

				break;

		}
	});

	return importKeypromise;
};