var socket_path = '/tmp/sshagent.sock';
var net = require('net');
var fs = require('fs');

var util = require('util');
var GUN = require('gun');
var SEA = require('gun/sea');
// var webrtc = require('gun/lib/webrtc');

var GUNDC = require("gun-dc");

var $crypto = require('crypto');

var helpers = require('./helpers.js');

var wrtc = require("wrtc");

// const server = require('http').createServer().listen(8765);

var gun = GUN({
    // RTCPeerConnection: wrtc.RTCPeerConnection,  
    // RTCSessionDescription: wrtc.RTCSessionDescription,  
    // RTCIceCandidate: wrtc.RTCIceCandidate,  
    axe: false,
    web: false,
    file: require("./__dirname.js") + "/radata2",
    peers: [
        "https://onlykey.herokuapp.com/gun",
        // "https://gun-manhattan.herokuapp.com/gun",
        "https://www.peersocial.io/gun"
    ]
    /*, peers: ["https://onlykey.herokuapp.com/gun", "https://gun-manhattan.herokuapp.com/gun"]*/
});

global._gun = gun;

var com_keys = false;
var com_keys_path = process.env.HOME + "/.ssh/sea_pair.json";

if (fs.existsSync(com_keys_path))
    com_keys = JSON.parse(fs.readFileSync(com_keys_path, { encoding: 'utf8', flag: 'r' }));

var hash = "p9O63w3zcXFJKJ2ES0iHFTzely/eqd5w6ScsUXdYSi4="
// + (new Date().getTime());
var hash_alias = $crypto.createHash('sha256').update(hash).digest().toString("hex");

var user = gun.user();

var gundc_connections = {};

function initUser(next) {
    // gun.get("~@"+hash_alias).once(function($user){
    //     if(!$user){

    //         user.create(hash_alias, hash, function(ack) {
    //             // console.log(ack);
    //             console.log("startup-create")
    //             global._user = user;
    //             next(user)
    //         });

    //     }else{

    // user.auth(hash_alias, hash, function(ack) {
    user.auth(com_keys, function(ack) {
        // console.log(ack);
        console.log("startup-login")
        global._user = user;
        next(user)
    });
    //     }
    // })
}

function startup(next) {

    if (!com_keys) {
        SEA.pair().then(function(pair) {
            com_keys = pair;
            fs.writeFileSync(com_keys_path, JSON.stringify(com_keys));
            initUser(next)
        });
    }
    else initUser(next);


}


function ready(user) {
    // console.log("ready")
    // var hash = "zar0gW9JWlOvvNkonTwGgXZIYUtdQ4k/B4DlC9x+2Zw=";

    function setup(pair) {
        var pubs = { epub: pair.epub, pub: pair.pub }

        // var pin = genPin(pair.epub + pair.pub)

        // console.log("pin", pin)
        console.log(pubs);
        // var pubkey = data_stringify({ data: pubs });

        if (!gundc_connections[hash]) {
            gundc_connections[hash] = GUNDC({ wrtc: wrtc, initiator: true, gun: gun, GUN: GUN, axe: false }, hash, pair);
            gundc_connections[hash].on("debug", console.log);
            gundc_connections[hash].on("connected", function(socket) {
                console.log("connected");
                socket.on("disconnected", function() {
                    console.log("socket disconnected");
                });
                
                // var callback_id = $crypto.randomInt(0, 100000000000).toString();
                // socket.emit("get_pub", callback_id);
                // socket.on(callback_id, function(data) {
                //     console.log(data)
                //     startServer(data, socket)
                // });
                
                socket.emit("get_pub", function(data) {
                    console.log(data)
                    startServer(data, socket)
                });

            });
            gundc_connections[hash].auth(function(pair, pass) {
                console.log("CONNECTION_PAIR", pair)
                pass();
            })
        }
        return;
        /*
                    gun.get("ok-" + hash).get("ok-pubkey").get("com").get(pubs.epub + "." + data_parse(pubkey).ts).on(async function(data) {
                        if (data) {
                            //  gun.get("ok-" + hash).get("ok-pubkey").get("remote").put(false);

                            var data_ts = data_parse(data).ts;
                            data = data_parse(data).data;
                            console.log(data);

                            var secret = await SEA.secret(data.epub, com_keys)

                            console.log("secret", secret)

                            if (!gundc_connections[secret]) {
                                gundc_connections[secret] = GUNDC({ wrtc: wrtc, initiator: true, gun: gun, GUN: GUN }, secret, pair);
                                gundc_connections[secret].on("debug", console.log);
                                gundc_connections[secret].on("connected", function(socket) {
                                    console.log("connected");
                                    socket.on("disconnected", function() {
                                        console.log("socket disconnected");
                                    });
                                });
                            }
                            // if(!peer2){
                            
                            // }
                            var pair_hash = $crypto.createHash('sha256').update(hash + pair.epub + pair.pub).digest();
                            var pin = genPin(pair_hash)

                            console.log("pin", pin)
                        }
                    });


                    // gun.get("ok-" + hash).get("ok-pubkey").get("remote").put(pubkey,console.log);
                    // setTimeout(function(){
                    gun.get("ok-" + hash).get("ok-pubkey").get("remote-in").put(pubkey);
                    // },5000)
        */

    }
    // setInterval(setup,1000)
    setup(com_keys);

    // setTime(function() {
    //   getPub(function(pub) {
    //     console.log(Buffer.from(pub, "hex").toString("base64"))
    //     startServer(pub)
    //   })

    // })



}


process.stdin.resume(); //so the program will not close instantly

function exitHandler(options, exitCode) {
    // if (options.cleanup){
    //   console.log('clean');
    // } 
    // if (exitCode || exitCode === 0)  console.log("exitCode",exitCode);
    if (options.exit) {
        for (var i in gundc_connections)
            gundc_connections[i].destroy();
        setTimeout(process.exit, 1000);
        // process.exit();
    }
}

//do something when app is closing
process.on('exit', exitHandler.bind(null, { cleanup: true }));
//catches ctrl+c event
process.on('SIGINT', exitHandler.bind(null, { exit: true }));
// catches "kill pid" (for example: nodemon restart)
process.on('SIGUSR1', exitHandler.bind(null, { exit: true }));
process.on('SIGUSR2', exitHandler.bind(null, { exit: true }));
//catches uncaught exceptions
process.on('uncaughtException', exitHandler.bind(null, { exit: true }));

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

function buildKeyBase64(pub_hex) {
    var _key = Buffer.from(pub_hex, "hex");
    var offset = 0;
    var kbt = Buffer.from(helpers.getCharCodes("ssh-ed25519"));
    var key = Buffer.alloc(4 + kbt.length + 4 + _key.length);

    helpers.ctype.wuint32(kbt.length, 'big', key, offset);
    offset += 4;
    kbt.copy(key, offset);
    offset = offset + kbt.length;
    helpers.ctype.wuint32(_key.length, 'big', key, offset);
    offset += 4;
    _key.copy(key, offset);
    return key.toString("base64");
}

function startServer(pub, socket) {

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
                            console.log("SSH2_AGENTC_REQUEST_IDENTITIES", len, type, JSON.stringify(response))
                            // var kbt = Buffer.from(helpers.getCharCodes("ssh-ed25519"));
                            // var _key = Buffer.from("439083de2ae68fd822a5b172d299403feecb96f25e299a8129ffde012aa649e2", "hex");
                            // var _key = Buffer.from(pub, "hex");


                            var key = Buffer.from(buildKeyBase64(Buffer.from(pub, "hex")), "base64");

                            console.log("key", key.toString("utf8"))

                            var request = Buffer.alloc(4 + 1 + 4 + 1 + 4 + key.length + 4);

                            offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH2_AGENT_IDENTITIES_ANSWER);
                            helpers.ctype.wuint32(1, 'big', request, offset);
                            offset += 4;

                            offset = helpers._writeString(request, key, offset);
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

                                console.log("indata", JSON.stringify(indata.str));
                                console.log("indata", indata.str.toString("utf8"));
                                console.log("indata", indata.len);


                                // var callback_id = $crypto.randomInt(0, 100000000000).toString();

                                socket.emit("sign_data", Array.from(indata.str), function(signature) {
                                    // signature = Buffer.from(signature.toString("HEX"));
                                    // signature = Buffer.from(signature.toString("base64"));
                                    // signature = Buffer.from(signature);
                                    signature = Buffer.from(signature)
                                    console.log("sig", signature);
                                    console.log("sig", signature.length);
                                    console.log("sig", JSON.stringify(signature.toString()));

                                    var kb_c = Buffer.from("ssh-ed25519");
                                    var resss = Buffer.alloc(4 + kb_c.length + 4 + signature.length)
                                    offset = 0;
                                    offset = helpers._writeString(resss, kb_c, offset);
                                    offset = helpers._writeString(resss, signature, offset);

                                    var request = Buffer.alloc(4 + 1 + 4 + resss.length);

                                    offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH2_AGENT_SIGN_RESPONSE);

                                    offset = helpers._writeString(request, resss, offset);
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

    fs.unlink(socket_path, function() {
        server.listen(socket_path, function() {
            console.log('server listening on path ' + socket_path);
        });
    });
};

startup(ready);
