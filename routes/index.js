var express = require('express');
var router = express.Router();
var functions = require('../crypto/functions');
var hashing = require('../crypto/DJCL/src/hashing').hashing;
var crypto = require('../crypto/subtlecrypto').crypto;


/* GET home page. */
var keyData = functions.convertPlainTextToArrayBufferView(functions.convertHexToString("2b7e151628aed2a6abf7158809cf4f3c"));
var algorithm = {name: 'HMAC', hash :{ name:'SHA-256' }, length : 256 };
var signalgo = {name : 'HMAC'};

var usages = ['sign','verify'];
var extractable = true;
var key = null;
var hash;

crypto.subtle.generateKey(algorithm, extractable, usages).then(function(result){
	key = result;
	//console.log(key);
	/*return crypto.subtle.sign(signalgo,key,functions.convertPlainTextToArrayBufferView("Hello")).then(function(res){
		console.log(functions.convertArrayBufferViewToPlainText(res));
	});*/
});


router.get('/', function(req, res) {
  	if (req.session.token){

	}
	else {
		//console.log(key);
		req.session.token = key;
	}
	//res.send(output);
	res.render('index', { token: JSON.stringify(req.session.token)});
});

router.post('/', function(req, res) {
	var msg="";
	var formcontent = req.body;
	for (var key in formcontent){
		if (key != "_csrf"){
			if (typeof(formcontent[key])=="object"){
				for (var counter = 0;counter<formcontent[key].length;counter++){
					msg += formcontent[key][counter];		
				}
			}
			else {
				msg += formcontent[key];	
			}
			
		}
	}
	
	//res.render('index', { token: 'Express' });
	var csrf = formcontent["_csrf"];
	token = req.session.token;
	var hash;
	console.log(crypto);
	crypto.subtle.verify(signalgo,token,functions.convertPlainTextToArrayBufferView(csrf),functions.convertPlainTextToArrayBufferView(msg)).then(function(result){
		hash = result;
		var content = "";
		if (!hash){
			content = "Invalid Hash";
		}
		else {
			content = "Valid hash";
		}
		res.send("Hash Computed at Client : <b>"+req.body["_csrf"]+"</b>\
				<br>\
				<b>"+content+"</b>\
				<br> \
				<br> Hash calculated of : <b>"+msg+"</b>\
				<br> Key used for HMAC : <b>"+JSON.stringify(token)+"</b>\
		");
	});
});

module.exports = router;
