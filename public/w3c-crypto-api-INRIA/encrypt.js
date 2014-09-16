/*
	Promise<any> encrypt(AlgorithmIdentifier algorithm, Key key, CryptoOperationData data);
*/

var encrypt = function(algorithm,key,data){

//TODO: Do we have to check key.algorithm.name = algorithm.name	
	var encryptpromise = new Promise(function(resolve,reject){

		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}
		var algo = algorithm.name;
		
		//If algorithm for sign is not in the suggested algorithms list,reject with DOMException Error
		if (encryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}
		
		

		if (!key.usages){
			reject("Key Usages not provided");
		}
		else if (key.usages.indexOf("encrypt")==-1){
			reject("InvalidAccessError");
		}

		switch(algo){
			case "AES-CBC":
				if (!algorithm.iv){
					reject("IV should be provided");
				}

				if (!algorithm.hasOwnProperty("iv")){
					reject("SyntaxError");
				}

				if (algorithm.iv.length != 16){
					reject("DataError");
				}

				var iv = convertArrayBufferViewToPlainText(algorithm.iv);
				
				data = convertArrayBufferViewToPlainText(data);

				var cipher;
				
				aes.setKey(convertArrayBufferViewToPlainText(key.data));
				
				cipher = aes.CBC(data,iv,false);
				cipher = convertPlainTextToArrayBufferView(cipher);
				resolve(cipher);
				
				break;
				
			case "RSA-OAEP":

				var label;
				if (!key.hasOwnProperty("type")){
					reject("Type of key is not provided");
				}
				else if (key.type!="public"){
					reject("InvalidAccessError");
				}

				if (!algorithm.hasOwnProperty("label")){
					label = "";
				}
				else {
					if (typeof(label)!="object"){
						reject ("label is not object");
					}
					else {
						label = algorithm.label;	
					}
					
				}

				var cipher;

				data = convertArrayBufferViewToPlainText(data);
				var publicK = key.data;
				cipher = rsa.encrypt(data,publicK);
				cipher = convertPlainTextToArrayBufferView(cipher);

				resolve(cipher);

				//TODO : Do something rsa.encrypt and some MGF
				//Points 4,5 and 6 of encrypt in RSA-OAEP
		}
	});

	return encryptpromise;	
};