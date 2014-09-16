function convertPlainTextToArrayBufferView(str) {
	var buf = new ArrayBuffer(str.length);
	var abv = new Uint8Array(buf);
	for (var i=0; i<str.length; ++i) {
		abv[i] = encoding.charCode(str[i]);
	}
	return abv;
}

//TODO : See how to use encoding.fromCharCode here.
function convertArrayBufferViewToPlainText(abv) {
	var str="";
	for (var i=0;i<abv.length;i++){
		str+=encoding.fromCharCode(abv[i]);
	}
	return str;
	//return String.fromCharCode.apply(null, new Uint8Array(abv));
}

function convertHexToString(hex){
	return encoding.hstr2astr(hex);
}

function convertStringToHex(string){
	return encoding.astr2hstr(string);
}

function checkRecognizedKeyUsageValues(keyUsages){
	var ans = false;
	for (var i=0; i<recognizedKeyUsageValues.length; i++){
		if (keyUsages.indexOf(recognizedKeyUsageValues[i])==-1){
			ans = ans || false;
		}
		else {
			ans = true;
			return ans;
		}
	}
	return ans;
}

function checkRecognizedKeyFormatValues(format){
	var ans = false;
	for (var i=0; i<recognizedKeyFormatValues.length; i++){
		if (recognizedKeyFormatValues.indexOf(format)==-1){
			ans = ans || false;
		}
		else {
			ans = true;
			return ans;
		}
	}
	return ans;
}