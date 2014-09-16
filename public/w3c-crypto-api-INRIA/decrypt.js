var decrypt = function(algorithm,key,data){

	var decryptpromise = new Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		
		if (!key){
			reject('Key not provided');
		}
		
		if (!algorithm.name){
			reject('Algorithm name not provided');
		}
			
		var algo = algorithm.name;

		//If algorithm for sign is not in the suggested algorithms list,reject with DOMException Error
		if (decryptalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}

		if (!key.usages){
			reject("Key Usages not provided");
		}
		else if (key.usages.indexOf("decrypt")==-1){
			reject("InvalidAccessError");
		}

		switch(algo){
			case "AES-CBC":

				if (!algorithm.hasOwnProperty("iv")){
					reject("SyntaxError");
				}
				
				if (!algorithm.iv){
					reject("IV shoud not be null");
				}

				if (algorithm.iv.length != 16){
					reject("DataError");
				}

				var iv = convertArrayBufferViewToPlainText(algorithm.iv);
				
				data = convertArrayBufferViewToPlainText(data);
				aes.setKey(convertArrayBufferViewToPlainText(key.data));
				
				var plaintext;
				plaintext = aes.CBC(data,iv,true);
				plaintext = convertPlainTextToArrayBufferView(plaintext);
				resolve(plaintext);
				break;

			case "RSA-OAEP":
				var label;
				if (!key.hasOwnProperty("type")){
					reject("Type of key is not provided");
				}
				else if (key.type!="private"){
					reject("InvalidAccessError");
				}

				if (!algorithm.hasOwnProperty("label")){
					label = "";
				}
				else {
					label = algorithm.label;
				}

				data = convertArrayBufferViewToPlainText(data);
				
				var plaintext;
				var privateKey = convertArrayBufferViewToPlainText(key.privateKey.data);
				plaintext = rsa.decrypt(convertStringToHex(data),privateKey);
				resolve(plaintext);

				//TODO : Do something rsa.decrypt and some MGF
				//Points 4,5 and 6 of encrypt in RSA-OAEP
				
		}	
	});
	return decryptpromise;
};