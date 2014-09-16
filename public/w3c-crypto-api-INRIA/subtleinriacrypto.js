//var crypto = document.createElement('div');
//TODO Check all reject values and fill them with DOMException as mentioned in the W3C Web Crytpo API
//TODO Replace all hasOwnProperty with ! . Go through each of them manually

var inriacrypto = {
	subtle : {
		encrypt : encrypt,
		decrypt : decrypt,
		sign : sign,
		verify : verify,
		digest : digest,
		generateKey : generateKey,
		deriveKey : deriveKey,
		importKey : importKey,
		exportKey : exportKey,
		wrapKey : wrapKey,
		unwrapKey : unwrapKey,
	},
};
