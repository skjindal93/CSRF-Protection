/*
	Promise<any> generateKey(AlgorithmIdentifier algorithm, boolean extractable, KeyUsage[] keyUsages);
*/
var generateKey = function(algorithm,extractable,keyUsages){

	var generateKeypromise = new Promise(function(resolve,reject){
		if (!algorithm){
			reject('Algorithm not provided');
		}
		else if (!algorithm.name){
			reject('Algorithm name not provided');
		}

		var algo = algorithm.name;

		//Check if the algo name is in the suggested algorithms
		if (generateKeyalgos.indexOf(algo)==-1){
			//Not correct. Check how to reject a DOMException
			reject(new DOMException(DOMException.NOT_SUPPORTED_ERR,"The algorithm is not supported"));
		}
		
		if (!keyUsages){
			reject("KeyUsages are not provided");
		}

		if (typeof(keyUsages)!="object"){
			reject("KeyUsages should be an array");
		}
		//Checking if the any of the value of keyUsages are in the Recognized Key Usage Values

		if (!checkRecognizedKeyUsageValues(keyUsages)){
			reject ("InvalidAccessError");
		}

		switch(algo){
			case "HMAC":
				var length;
				
				//If hash member is not present in algorithm, return SyntaxError
				//Point 2: Generate Key in HMAC
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}

				//Point 3: Generate Key HMAC
				if (!algorithm.hasOwnProperty("length")){
					reject("Length is not provided");
				}
				//Check whether !=0 or just >0
				else if (algorithm.length>0){
					length = algorithm.length;
				}
				else {
					reject("Data Error");
				}

				if (!algorithm.hash.name){
					reject("Name of hash algorithm not provided");
				}
				else if (algorithm.hash.name!="SHA-1" && algorithm.hash.name!="SHA-256"){
					reject("Not supported hash algorithm");
				}

				//Point 4: Generate Key HMAC
				if (keyUsages.indexOf("sign")==-1 && keyUsages.indexOf("verify")==-1){
					reject ("DataError");
				}
				
				//hashKeyAlgorithm: new Key Algorithm
				var hashKeyAlgorithm = {
					name : algorithm.hash.name,
				}

				//new HmacKeyAlgorithm, though there is no name attribute in HmacKeyAlgorithm 
				//still attribute name assigned as said in Point 9
				var HmacKeyAlgorithm = {	
					name : "HMAC",
					hash : hashKeyAlgorithm,	
				}

				//TODO : Generate some random key using the length attribute
				var array = new Uint8Array(length/8);
				//crypto.getRandomValues(array);
				var randomKey = array;

				var key = {
					//Since HMAC is a symmetric algorithm, so type : "secret"
					type : "secret",
					extractable : extractable,
					algorithm : HmacKeyAlgorithm,
					usages : keyUsages,
					data : randomKey
				};
				
				resolve(key);
				break;

			case "AES-CBC":

				var length;

				if (!algorithm.hasOwnProperty("name")){
					reject("SyntaxError");
				}

				if (!algorithm.hasOwnProperty("length")){
					reject("SyntaxError");
				}
				//Check whether !=0 or just >0

				else if (algorithm.length!=128 && algorithm.length!=192 && algorithm.length!=256){
					reject("Data Error");
					
				}
				else {
					length = algorithm.length;
				}

				if (keyUsages.indexOf("encrypt")==-1 && keyUsages.indexOf("decrypt")==-1 && keyUsages.indexOf("wrapKey")==-1 && keyUsages.indexOf("unwrapKey")==-1){
					reject ("DataError");
				}

				//new AeKeyAlgorithm, though there is no name attribute in AesKeyAlgorithm 
				//still attribute name assigned as said in Point 9
				var AesKeyAlgorithm = {	
					name : "AES-CBC",
					length : length
				}

				//TODO : Generate some random key using the length attribute
				var array = new Uint8Array(length/8);
				//crypto.getRandomValues(array);
				var randomKey = array;

				var key = {
					//Since HMAC is a symmetric algorithm, so type : "secret"
					type : "secret",
					extractable : extractable,
					algorithm : AesKeyAlgorithm,
					usages : keyUsages,
					data : randomKey
				};
				
				resolve(key);
				break;

			case "RSA-OAEP":
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("modulusLength")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("publicExponent")){
					reject("SyntaxError");
				}

				if (keyUsages.indexOf("encrypt")==-1 && keyUsages.indexOf("decrypt")==-1 && keyUsages.indexOf("wrapKey")==-1 && keyUsages.indexOf("unwrapKey")==-1){
					reject ("InvalidAccessError");
				}

				//TODO: Generate RSA key pair
				//DJCL must have a generate function in RSA

				var publicKey;
				publicKey.n = "00b9c9dcfee60b324230f14de9234ef75f0b7f9bc9730f0eccd3f1cf980f7784d39f4c47002187e193551c7d63f24a74bf0f4f1ab567ba594c279ee4479fa1e35d";
				publicKey.e = "010001";

				var privateKey;
				privateKey.n = "00a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137";
				privateKey.e = "010001";
				privateKey.d = "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325";
				privateKey.p = "00e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443";
				privateKey.q = "00b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd";
				privateKey.dmp1 = "28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979";
				privateKey.dmq1 = "1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729";
				privateKey.iqmp = "27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d";
				var keyPair = {};

				var RsaHashedKeyAlgorithm = {
					name : "RSA-OAEP",
					modulusLength : algorithm.modulusLength,
					publicExponent : algorithm.publicExponent,
					hash : algorithm.hash,
				};

				keyPair.publicKey = {
					type : "public",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : true,
					data : publicKey,
					//TODO : Get public Key data from rsa_generate
					//TODO : Intersection of keyUsages and ["encrypt","wrapKey"]
					usages : keyUsages
				};

				keyPair.privateKey = {
					type : "private",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : extractable,
					data : privateKey,
					//TODO : Get private Key data from rsa_generate
					//TODO : Intersection of keyUsages and ["decrypt","unwrapKey"]
					usages : keyUsages,
				};

				resolve(keyPair);
				break;

			case "RSASSA-PKCS1-v1_5":
				if (!algorithm.hasOwnProperty("hash")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("modulusLength")){
					reject("SyntaxError");
				}
				else if (!algorithm.hasOwnProperty("publicExponent")){
					reject("SyntaxError");
				}

				if (keyUsages.indexOf("sign")==-1 && keyUsages.indexOf("verify")==-1){
					reject ("DataError");
				}

				//TODO: Generate RSA key pair
				//DJCL must have a generate function in RSA
				var publicKey;
				publicKey.n = "00b9c9dcfee60b324230f14de9234ef75f0b7f9bc9730f0eccd3f1cf980f7784d39f4c47002187e193551c7d63f24a74bf0f4f1ab567ba594c279ee4479fa1e35d";
				publicKey.e = "010001";

				var privateKey;
				privateKey.n = "00a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137";
				privateKey.e = "010001";
				privateKey.d = "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325";
				privateKey.p = "00e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443";
				privateKey.q = "00b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd";
				privateKey.dmp1 = "28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979";
				privateKey.dmq1 = "1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729";
				privateKey.iqmp = "27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d";
				
				var keyPair = {};

				var RsaHashedKeyAlgorithm = {
					name : "RSASSA-PKCS1-v1_5",
					modulusLength : algorithm.modulusLength,
					publicExponent : algorithm.publicExponent,
					hash : algorithm.hash
				};

				keyPair.publicKey = {
					type : "public",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : true,
					data : publicKey,
					//TODO : Intersection of keyUsages and ["verify"]
					usages : keyUsages
				};

				keyPair.privateKey = {
					type : "private",
					algorithm : RsaHashedKeyAlgorithm,
					extractable : extractable,
					data : privateKey,
					//TODO : Intersection of keyUsages and ["sign"]
					usages : keyUsages,
				};

				resolve(keyPair);
				break;


		}
	});

	return generateKeypromise;
};