var socket_path = '/tmp/sshagent.sock';
var net = require('net');
var fs = require('fs');

var util = require('util');

var helpers = require('./helpers.js');

fs.unlink(socket_path, function() {
  setTime(function() {
    getPub(function(pub) {
      console.log(Buffer.from(pub, "hex").toString("base64"))
      startServer(pub)
    })

  })


});

function hexStrToDec(hexStr) {
  return ~~(new Number('0x' + hexStr).toString(10));
};
function MissingEnvironmentVariableError(variable) {
  this.name = 'MissingEnvironmentVariableError';
  this.message = variable + ' was not found in your environment';
  this.variable = variable;
  Error.captureStackTrace(this, MissingEnvironmentVariableError);
}
util.inherits(MissingEnvironmentVariableError, Error);


function TimeoutError(message) {
  this.name = 'TimeoutError';
  this.message = message;
  Error.captureStackTrace(this, TimeoutError);
}
util.inherits(TimeoutError, Error);


function InvalidProtocolError(message) {
  this.name = 'InvalidProtocolError';
  this.message = message;
  Error.captureStackTrace(this, InvalidProtocolError);
}
util.inherits(InvalidProtocolError, Error);


/*
    SSH_AGENTC_REQUEST_IDENTITIES                  11
    SSH_AGENTC_SIGN_REQUEST                        13
    SSH_AGENTC_ADD_IDENTITY                        17
    SSH_AGENTC_REMOVE_IDENTITY                     18
    SSH_AGENTC_REMOVE_ALL_IDENTITIES               19
    SSH_AGENTC_ADD_ID_CONSTRAINED                  25
    SSH_AGENTC_ADD_SMARTCARD_KEY                   20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY                21
    SSH_AGENTC_LOCK                                22
    SSH_AGENTC_UNLOCK                              23
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED       26
    SSH_AGENTC_EXTENSION                           27
    
    The following numbers are used for replies from the agent to the client.

    SSH_AGENT_FAILURE                               5
    SSH_AGENT_SUCCESS                               6
    SSH_AGENT_EXTENSION_FAILURE                     28
    SSH_AGENT_IDENTITIES_ANSWER                     12
    SSH_AGENT_SIGN_RESPONSE                         14
    
    The following numbers are used to identify key constraints. These are only used in key constraints and are not sent as message numbers.
    
    SSH_AGENT_CONSTRAIN_LIFETIME                    1
    SSH_AGENT_CONSTRAIN_CONFIRM                     2
    SSH_AGENT_CONSTRAIN_EXTENSION                   3
    
    The following numbers may be present in signature request (SSH_AGENTC_SIGN_REQUEST) messages. These flags form a bit field by taking the logical OR of zero or more flags.

    SSH_AGENT_RSA_SHA2_256                          2
    SSH_AGENT_RSA_SHA2_512                          4
*/

function startServer(pub) {

  function route(stream) {
    //console.log('client connected');

    stream.on('end', function() {
      // console.log('client disconnected');
    });

    stream.on('error', function(err) {
      console.log(err);
      // stream.write({ error: err.toString() });
    });

    var write = stream.write;

    // stream.write = function() {
    //   var args = arguments;
    //   if (typeof args[0] == 'object') {
    //     args[0] = JSON.stringify(args[0]) + '\n';
    //   }
    //   write.apply(stream, args);
    // };

    // stream.write(BANNER);
    //  https://tools.ietf.org/id/draft-miller-ssh-agent-01.html#messagenum
    var msgdata = [];
    var len = 0;
    var type = -1;
    stream
      // .pipe(split())
      // .pipe(parse())
      .on('data', function(response) {
        console.log("resp",response.length, response);
        
        if(len == 0 && response.length == 4){
          len = helpers.ctype.ruint32(response, 'big', 0);
          return;
        }else if(response.length == 1){
          type = response[0];
          len = 1;
        }else{
          len = helpers.ctype.ruint32(response, 'big', 0);
          type = helpers.ctype.ruint8(response, 'big', 4);
        }
        console.log("len",len);
        
        // msgdata = msgdata.concat(Array.from(response))
        
        // console.log("response",response);
        // return;
        
        try {
          console.log("req-type", type)
          console.log("data-in", Buffer.from(response))

          // var len, type;

          // if (response.length == 1 && Buffer.from(response)[0] == 11) {
          //   len = 1;
          //   type = 11;
          //   return;
          // }
          // else {
          //   len = helpers.ctype.ruint32(response, 'big', 0);
          //   console.log(len);
          //   // type = helpers.ctype.ruint8(response, 'big', 4);
          // }
          var offset;
          switch (type) {
            // case 13:
            //   /*

            //   */
            //   console.log("SIGNREQUEST")
            //   console.log(response)
            //   break;

            case helpers.PROTOCOL.SSH_AGENTC_REQUEST_RSA_IDENTITIES:
              break;
            case helpers.PROTOCOL.SSH2_AGENTC_REQUEST_IDENTITIES:
              console.log("list pubkeys")
              var kbt = Buffer.from(helpers.getCharCodes("ssh-ed25519"));
              // var _key = Buffer.from("439083de2ae68fd822a5b172d299403feecb96f25e299a8129ffde012aa649e2", "hex");
              var _key = Buffer.from(pub, "hex");

              var key = Buffer.alloc(4 + kbt.length + 4 + _key.length);

              offset = 0;

              helpers.ctype.wuint32(kbt.length, 'big', key, offset);
              offset += 4;
              kbt.copy(key, offset);
              offset = offset + kbt.length;

              // offset = _writeString(key, kbt, offset);
              // _writeString(key, _key, offset);
              // offset += 4;

              helpers.ctype.wuint32(_key.length, 'big', key, offset);
              offset += 4;
              _key.copy(key, offset);
              offset = offset + kbt.length;

              // var kb_c = Buffer.from("ok");
              var request = Buffer.alloc(4 + 1 + 4 + 1 + 4 + key.length + 4);
              // var request = new Buffer(4 + 1 + 4 + key._raw.length + 4 + data.length + 4);
              // var offset = _writeHeader(request, PROTOCOL.SSH2_AGENTC_SIGN_REQUEST);
              // offset = _writeString(request, key._raw, offset);
              // offset = _writeString(request, data, offset);
              // ctype.wuint32(0, 'big', request, offset);
              // return request;

              offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH2_AGENT_IDENTITIES_ANSWER);
              helpers.ctype.wuint32(1, 'big', request, offset);
              offset += 4;
              offset = helpers._writeString(request, key, offset);
              // offset = helpers._writeString(request, kb_c, offset);
              helpers.ctype.wuint32(0, 'big', request, offset);

              stream.write(request);
              console.log("sent",request);
              break;
            case helpers.PROTOCOL.SSH2_AGENTC_SIGN_REQUEST:

              offset = 0;

              console.log("SSH2_AGENTC_SIGN_REQUEST", len, type, JSON.stringify(response))

              response = response.slice(5, len);
              
              if (response.length) {
                var blobkey = helpers._readString(response, offset);
                offset += 4 + blobkey.len;
                var indata = helpers._readString(response, offset);


                // var signature = _readString(blob, type.length + 4);
                var id = JSON.stringify(Array.from(indata.str)).split(",0,0,0,");

                console.log(id);
                id = JSON.stringify(Array.from(indata.str));
                
                var offset2 = 0;
                var hash = helpers._readString(indata.str, offset2);
                
                console.log(JSON.stringify(hash.str))
                
                // return;

                console.log("indata", JSON.stringify(indata.str));
                console.log("indata", indata.str.toString("utf8"));
                console.log("indata", indata.len);
                sign({
                  blob: blobkey.str.toString("base64"),
                  indata: indata.str, // <-- sign this
                  // signature: signature.toString('base64'),
                  // _raw: signature
                }, function(signature) {
                  // signature = Buffer.from(signature.toString("HEX"));
                  // signature = Buffer.from(signature.toString("base64"));
                  // signature = Buffer.from(signature);
                  console.log("sig", signature);
                  console.log("sig", signature.length);
                  console.log("sig", JSON.stringify(signature.toString()));
                  
                  var kb_c = Buffer.from("ssh-ed25519");
                  var resss = Buffer.alloc(4 + kb_c.length + 4 + signature.length )
                  offset = 0;
                  offset = helpers._writeString(resss, kb_c, offset);
                  offset = helpers._writeString(resss, signature, offset);
                  
                  var request = Buffer.alloc(4 + 1 + 4 + resss.length);
                  // var request = new Buffer(4 + 1 + 4 + key._raw.length + 4 + data.length + 4);
                  // var offset = _writeHeader(request, PROTOCOL.SSH2_AGENTC_SIGN_REQUEST);
                  // offset = _writeString(request, key._raw, offset);
                  // offset = _writeString(request, data, offset);
                  // ctype.wuint32(0, 'big', request, offset);
                  // return request;

                  offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH2_AGENT_SIGN_RESPONSE);
                  // helpers.ctype.wuint32(signature.length, 'big', request, offset);
                  // offset += 4;
                  // offset = helpers._writeString(request, kb_c, offset);
                  // offset = helpers._writeString(request, signature, offset);
                  offset = helpers._writeString(request, resss, offset);
                  // offset = helpers._writeString(request, kb_c, offset);
                  // helpers.ctype.wuint32(0, 'big', request, offset);

                  stream.write(request);

                  console.log("sending response", request)
                  console.log("sending response", JSON.stringify(request))

                });
              }
              break;

              // var request = Buffer.alloc(4 + 1 + 4 + 1 + 4 );
              // offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH_AGENT_SUCCESS);
              // helpers.ctype.wuint32(0, 'big', request, offset);

              // stream.write(request);
              // break;
            default:
              // var kb_c = Buffer.from("ok");
              var request = Buffer.alloc(4 + 1 + 4 + 1 + 4);
              // var request = new Buffer(4 + 1 + 4 + key._raw.length + 4 + data.length + 4);
              // var offset = _writeHeader(request, PROTOCOL.SSH2_AGENTC_SIGN_REQUEST);
              // offset = _writeString(request, key._raw, offset);
              // offset = _writeString(request, data, offset);
              // ctype.wuint32(0, 'big', request, offset);
              // return request;

              offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH_AGENT_FAILURE);
              // helpers.ctype.wuint32(1, 'big', request, offset);
              // offset += 4;
              // offset = helpers._writeString(request, signature, offset);
              // offset = helpers._writeString(request, kb_c, offset);
              helpers.ctype.wuint32(0, 'big', request, offset);

              stream.write(request);
              console.log("fail");
              break;
          }


        }
        catch (e) { console.log(e) }
        // for(var i in events) {
        //   if (events[i].test(stream, data)) {
        //     events[i].handler(stream, data);
        //   }
        // }
        len = 0;
        type = -1;
      });

  }

  var server = net.createServer(route);

  server.listen(socket_path, function() {
    console.log('server listening on path ' + socket_path);
  });
};


/*
var optimist = require('optimist')
	.usage('Usage: $0 --cmd [cmd]')
	.demand('cmd')
	.describe('cmd', 'Command to run settime , getlables')
	.alias('cmd', 'c')
	.describe('slot', 'slot id to choose')
	.alias('slot', 's')
	.describe('data', 'additional data')
	.alias('data', 'd')
	.describe('blob', 'blob data')
	.alias('blob', 'b')
	.describe('keytype', 'keytype')
	.alias('keytype', 't')
	.describe('help', 'Show Help')
	.alias('help', 'h').alias('help', '?');

var argv = optimist.argv;

if (argv.help) {
	return optimist.showHelp();
}
*/


const nodeHID = require('node-hid');

const messageHeader = [255, 255, 255, 255];

const messageFields = {
  LABEL: 1,
  URL: 15,
  NEXTKEY4: 18, //Before Username
  NEXTKEY1: 16, //After Username
  DELAY1: 17,
  USERNAME: 2,
  NEXTKEY5: 19, //Before OTP
  NEXTKEY2: 3, //After Password
  DELAY2: 4,
  PASSWORD: 5,
  NEXTKEY3: 6, //After OTP
  DELAY3: 7,
  TFATYPE: 8,
  TFAUSERNAME: 9,
  YUBIAUTH: 10,
  LOCKOUT: 11,
  WIPEMODE: 12,
  BACKUPKEYMODE: 20,
  SSHCHALLENGEMODE: 21,
  PGPCHALLENGEMODE: 22,
  SECPROFILEMODE: 23,
  TYPESPEED: 13,
  LEDBRIGHTNESS: 24,
  LOCKBUTTON: 25,
  KBDLAYOUT: 14
};

const messages = {
  OKSETPIN: 225, //0xE1
  OKSETSDPIN: 226, //0xE2
  OKSETPIN2: 227, //0xE3
  OKSETTIME: 228, //0xE4
  OKGETLABELS: 229, //0xE5
  OKSETSLOT: 230, //0xE6
  OKWIPESLOT: 231, //0xE7
  OKSETU2FPRIV: 232, //0xE8
  OKWIPEU2FPRIV: 233, //0xE9
  OKSETU2FCERT: 234, //0xEA
  OKWIPEU2FCERT: 235, //0xEB
  OKGETPUBKEY: 236,
  OKSIGN: 237,
  OKWIPEPRIV: 238,
  OKSETPRIV: 239,
  OKDECRYPT: 240,
  OKRESTORE: 241,
  OKFWUPDATE: 244,
};

/*
switch (argv.cmd) {
	case 'settime':
		setTime();
		break;

	case 'getlabels':
		getLabels();
		break;

	case 'getpub':
		getPub();
		break;

	case 'sign':
		sign();
		break;

	case 'dotest':
		dotest();
		break;

	default:

		console.log("argv", argv);

}*/

function findHID(hid_interface) {
  var hids = nodeHID.devices();

  //console.log(hids);

  for (var i in hids) {
    if (hids[i].product == "ONLYKEY") {
      if (hids[i].interface == hid_interface) {
        return hids[i];
      }
    }
  }
}

function sendMessage(com, options) {

  var msgId = typeof options.msgId === 'string' ? options.msgId.toUpperCase() : null;
  var slotId = typeof options.slotId === 'number' || typeof options.slotId === 'string' ? options.slotId : null;
  var contents = typeof options.contents === 'number' || (options.contents && options.contents.length) ? options.contents : '';

  var reportId = 0;

  var bytes = [].concat(messageHeader);

  bytes.push(messages[msgId]);

  var messageA, temporary;

  for (var i = 0; i < contents.length; i++) {
    if (typeof contents[i] == "string")
      contents[i] = parseInt(hexStrToDec(contents[i]), 10);
    else
      contents[i] = contents[i];
  }

  if (!contents) {

    if (slotId !== null) {
      bytes.push(slotId);
    }
    messageA = Array.from(bytes);
    temporary = [].concat(messageA);
    for (; 64 > temporary.length;) {
      temporary.push(0);
    }
    com.write([reportId].concat(temporary));
  }
  else {
    messageA = Array.from(bytes);
    if (contents.length > 57) {
      var chunkLen = (64 - messageA.length) - 2;
      var i, j, chunk = chunkLen;
      for (i = 0, j = contents.length; i < j; i += chunk) {
        var _chunk = contents.slice(i, i + chunk);

        temporary = [].concat(messageA).concat([slotId, _chunk.length < chunkLen ? _chunk.length : 255]).concat(_chunk);

        for (; 64 > temporary.length;) {
          temporary.push(0);
        }

        com.write([reportId].concat(temporary));
      }
    }
    else {
      if (slotId !== null) {
        bytes.push(slotId);
      }
      messageA = Array.from(bytes);
      temporary = [].concat(messageA).concat(contents);
      com.write([reportId].concat(temporary));
    }

  }
}

function setTime(done) {


  var hid = findHID(2);

  if (hid) {
    var com = new nodeHID.HID(hid.path);
    com.path = hid.path;

    com.on("data", function(msg) {
      var msg_string = bytes2string(msg);

      // console.log("handleMessage", msg, msg_string);
      if (msg_string == "INITIALIZED")
        console.log("OnlyKey Locked");
      else if (msg_string.split("v")[0] == "UNLOCKED") {
        console.log("OnlyKey UnLock... Time Set!");
        if (done) done();
      }
      com.close();

    });


    var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
    // console.info("Setting current epoch time =", currentEpochTime);
    var timeParts = currentEpochTime.match(/.{2}/g);
    var options = {
      contents: timeParts,
      msgId: 'OKSETTIME'
    };
    sendMessage(com, options);

    //console.log(hid);
  }
  else {
    console.log("onlykey not detected");
  }

}


function getPub(done) {


  var hid = findHID(2);

  if (hid) {
    var com = new nodeHID.HID(hid.path);
    com.path = hid.path;

    com.on("data", function(msg) {

      msg = Array.from(msg);
      console.log("full-msg", msg)
      msg = msg.splice(0, 32);
      msg = Buffer.from(msg);

      com.close();
      
      console.log(JSON.stringify(Buffer.from(msg)))
      if (done)
        done(msg.toString("hex"));

    });
    var crypto = require('crypto');
    var slot = 132; //argv.slot ? parseInt(argv.slot, 10) : 132;
    var hash;

    if (slot == 132) {
      hash = crypto.createHash('sha256').update("localhost").digest();
    }
    else hash = '';
    hash = Array.from(hash);

    hash = [1].concat(hash);

    var options = {
      contents: hash,
      slotId: parseInt(slot, 10),
      msgId: 'OKGETPUBKEY'
    };

    sendMessage(com, options);

  }
  else {
    console.log("onlykey not detected");
  }

}



function sign(data, done) {


  var hid = findHID(2);

  if (hid) {
    var com = new nodeHID.HID(hid.path);
    com.path = hid.path;

    com.on("data", function(msg) {

      if (msg.toString("utf8").indexOf("Error device locked") == 0)
        return;

      console.log("res",msg.length,  JSON.stringify(Buffer.from(msg)));
      msg = Array.from(msg);

      msg = msg.splice(0, 64);
      msg = Buffer.from(msg);

      com.close();

      if (done)
        done(msg, data);

    });
    var crypto = require('crypto');
    var slot = 201; //argv.slot ? parseInt(argv.slot, 10) : 201;

    var hash = data.indata;//crypto.createHash('sha256').update(data.indata).digest();
    var blob = crypto.createHash('sha256').update("localhost").digest(); //.toString("hex");


    hash = Array.from(hash);
    hash = [].concat(hash);
    blob = Array.from(blob); //.slice(0,16);
    blob = [].concat(blob);

    var options = {
      contents: [].concat(hash).concat(blob),
      slotId: parseInt(slot, 10),
      msgId: 'OKSIGN'
    };

    sendMessage(com, options);

  }
  else {
    console.log("onlykey not detected");
  }

}

/*
async function getLabels() {

	var hid = findHID(2);

	if (hid) {
		var com = new nodeHID.HID(hid.path);
		com.path = hid.path;

		var messCount = 0;

		com.on("data", function(msg) {
			messCount += 1;
			msg = Array.from(msg);

			var msg_string = bytes2string(msg);

			// console.log("handleMessage", msg, msg_string);
			if (msg_string == "INITIALIZED")
				console.log("OnlyKey Locked");
			else if (msg_string.split("v")[0] == "UNLOCKED")
				console.log("OnlyKey UnLock... Time Set!");

			var slot = msg.shift();
			msg_string = bytes2string(msg);

			if (slot > 9) slot -= 6

			console.log("Slot:", slot, msg_string.split("|"))

			if (messCount == 12)
				com.close();
		});



		sendMessage(com, {
			msgId: 'OKGETLABELS'
		});

		//console.log(hid);
	}
	else {
		console.log("onlykey not detected");
	}

};

async function dotest() {
	getPub(function(pub) {

		sign(function(sig, data) {


			var nacl = require("tweetnacl");

			var forge = require("node-forge");


			var md = forge.md.sha256.create();
			md.update(data, 'utf8');
			md = Uint8Array.from(Buffer.from(md.digest().toHex(), "hex"));

			var _sig = Uint8Array.from(Buffer.from(sig, 'base64'))

			var pk = Uint8Array.from(Buffer.from(pub, 'base64'));

			console.log("i have pub", pub)
			console.log("i have sig", sig)
			console.log("TEST", nacl.sign.detached.verify(md, _sig, pk) ? "PASSED" : "FAILED")

		});
	})
}
*/
function hexStrToDec(hexStr) {
  return new Number('0x' + hexStr).toString(10);
}

function bytes2string(bytes) {
  if (!bytes) return;
  var ret = Array.from(bytes).map(function chr(c) {
    if (c == 0) return '';
    if (c == 255) return '';
    return String.fromCharCode(c);
  }).join('');
  return ret;
};
