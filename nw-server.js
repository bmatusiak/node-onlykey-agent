var socket_path = '/tmp/sshagent.sock';
var net = require('net');
var fs = require('fs');

var util = require('util');
var GUN = require('gun');
var SEA = require('gun/sea');
var webrtc = require('gun/lib/webrtc');

var $crypto = require('crypto');

var helpers = require('./helpers.js');

const server = require('http').createServer().listen(8765);

var gun = GUN({ web: server, peers: ["http://localhost:8765/gun", "https://onlykey.herokuapp.com/gun", "https://gun-manhattan.herokuapp.com/gun"] });

global._gun = gun;

var com_keys = false;
var com_keys_path = process.env.HOME + "/.ssh/sea_pair.json";

if (fs.existsSync(com_keys_path))
    com_keys = JSON.parse(fs.readFileSync(com_keys_path, { encoding: 'utf8', flag: 'r' }));

if (!com_keys) {
    SEA.pair().then(function(pair) {
        com_keys = pair;
        fs.writeFileSync(com_keys_path, JSON.stringify(com_keys));
        ready()
    });
}
else ready();

var Peer = require('simple-peer');
var wrtc = require('wrtc');

// var peer1 = new Peer({ initiator: true, wrtc: wrtc });
// var peer2 = new Peer({ wrtc: wrtc });
//  peer2.on('connect', () => {
//       // wait for 'connect' event before using the data channel
//       peer2.send('hey peer1, how is it going?')
// })

// peer2.on('data', data => {
//   // got a data channel message
//   console.log('got a message from peer2: ' + data)
// })

/*peer1.on('signal', data => {
  // when peer1 has signaling data, give it to peer2 somehow
  peer2.signal(data)
})

peer2.on('signal', data => {
  // when peer2 has signaling data, give it to peer1 somehow
  peer1.signal(data)
})

peer1.on('connect', () => {
  // wait for 'connect' event before using the data channel
  peer1.send('hey peer2, how is it going?')
})

peer2.on('data', data => {
  // got a data channel message
  console.log('got a message from peer1: ' + data)
})
*/
// var peer2;
function ready() {

    fs.unlink(socket_path, function() {
        var hash = "zar0gW9JWlOvvNkonTwGgXZIYUtdQ4k/B4DlC9x+2Zw=";

        function setup(pair) {
            var pubs = { epub: pair.epub, pub: pair.pub }

            var pin = genPin(pair.epub + pair.pub)

            console.log("pin", pin)
            console.log(pubs);
            var pubkey = data_stringify({ data: pubs });

            gun.get("ok-" + hash).get("ok-pubkey").get("com").get(pubs.epub + "." + data_parse(pubkey).ts).on(async function(data) {
                if (data) {
                     gun.get("ok-" + hash).get("ok-pubkey").get("remote").put(null);
                     
                    var data_ts = data_parse(data).ts;
                    data = data_parse(data).data;
                    console.log(data);

                    var sec = await SEA.secret(data.epub, com_keys)

                    console.log("secret", sec)
                    // if(!peer2){
                    var peer2 = new Peer({ wrtc: wrtc });
                    peer2.on('connect', () => {
                        // wait for 'connect' event before using the data channel
                        
                        setInterval(function(){
                            peer2.send(data_stringify({data:'hey peer1, how is it going?'}))    
                        },1000)
                    })

                    peer2.on('data', data => {
                        // got a data channel message
                        data = data_parse(data);
                        console.log(data)
                    })
                    var shash = $crypto.createHash('sha256').update(data_parse(pubkey).ts + sec).digest().toString("hex");
                    console.log("shash", shash)
                    gun.get(shash).get("peer1").get("signal").on(async function(data) {
                        data = await SEA.decrypt(data_parse(data).data, sec);
                        peer2.signal(data)

                    })

                    peer2.on("signal", async function(data) {
                        var d = data_stringify({ data: await SEA.encrypt(data, sec) })
                        gun.get(shash).get("peer2").get("signal").put(d)
                    });
                    // }
                    var pair_hash = $crypto.createHash('sha256').update(hash + pair.epub + pair.pub).digest();
                    var pin = genPin(pair_hash)

                    console.log("pin", pin)
                }
            });

            gun.get("ok-" + hash).get("ok-pubkey").get("remote").put(pubkey);


        }
        // setInterval(setup,1000)
        setup(com_keys);

        // setTime(function() {
        //   getPub(function(pub) {
        //     console.log(Buffer.from(pub, "hex").toString("base64"))
        //     startServer(pub)
        //   })

        // })


    });

}

// pin = [get_pin(pin_hash[0]), get_pin(pin_hash[15]), get_pin(pin_hash[31])];

function genPin(pin_data) {
    var pin_hash = $crypto.createHash('sha256').update(pin_data).digest();
    var pid = 0;
    return [
        get_pin(pin_hash[pid]),
        get_pin(pin_hash[pid += 4]),
        get_pin(pin_hash[pid += 4]),
        get_pin(pin_hash[pid += 4]),
        get_pin(pin_hash[pid += 4]),
        get_pin(pin_hash[pid += 4]),
        get_pin(pin_hash[pid += 4]),
        get_pin(pin_hash[pid += 4])
    ];
}

function get_pin(byte) {
    return (byte % 9) + 1;
}

function data_stringify(data) {
    if (data.data) {
        return "JSON" + JSON.stringify({ data: data.data, ts: new Date().getTime() });
    }
    else {
        return JSON.stringify(data);
    }
}

function data_parse(data) {
    if (data)
        if (data.slice(0, 4) == "JSON") {
            return JSON.parse(data.slice(4));
        }
    else {
        return JSON.parse(data);
    }
}

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
                console.log("resp", response.length, response);

                if (len == 0 && response.length == 4) {
                    len = helpers.ctype.ruint32(response, 'big', 0);
                    return;
                }
                else if (response.length == 1) {
                    type = response[0];
                    len = 1;
                }
                else {
                    len = helpers.ctype.ruint32(response, 'big', 0);
                    type = helpers.ctype.ruint8(response, 'big', 4);
                }
                console.log("len", len);

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
                            console.log("sent", request);
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
                                    var resss = Buffer.alloc(4 + kb_c.length + 4 + signature.length)
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
