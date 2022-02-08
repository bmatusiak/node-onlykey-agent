var socket_path = '/tmp/sshagent.sock';
var net = require('net');
var fs = require('fs');

var util = require('util');

global._console = console;
// global.console = {log:function(){}};
// global.window = {console:global.console};

var GUN = require('gun');

// for(var i in global.window){
//     global[i] = global.window[i];
// }

global.console = global._console;
// delete global._console;

// GUN.window = false;
// delete global.window;
// Gun.log = console.log;
// Gun.log.once = console.log;

var SEA = require('gun/sea');

var GUNDC = require("gun-dc");

var $crypto = require('crypto');

var helpers = require('./helpers.js');

var wrtc = require("wrtc");


var gun = GUN({
    axe: false,
    web: false,
    file: require("./__dirname.js") + "/radata2",
    peers: [
        "https://onlykey.herokuapp.com/gun",
        "https://www.peersocial.io/gun"
    ]
});

global._gun = gun;

var com_keys = false;
var com_keys_path = process.env.HOME + "/.ssh/sea_pair.json";

if (fs.existsSync(com_keys_path))
    com_keys = JSON.parse(fs.readFileSync(com_keys_path, { encoding: 'utf8', flag: 'r' }));

var hash = "p9O63w3zcXFJKJ2ES0iHFTzely/eqd5w6ScsUXdYSi4=";

var user = gun.user();

var gundc_connections = {};

function initUser(next) {
    user.auth(com_keys, function(ack) {
        global._user = user;
        next(user);
    });
}

function startup(next) {
    if (!com_keys) {
        SEA.pair().then(function(pair) {
            com_keys = pair;
            fs.writeFileSync(com_keys_path, JSON.stringify(com_keys));
            initUser(next);
        });
    }
    else initUser(next);
}


function ready(user) {
    function setup(pair) {
        var pubs = { epub: pair.epub, pub: pair.pub };
        // console.log(pubs);

        if (!gundc_connections[hash]) {
            gundc_connections[hash] = GUNDC({ wrtc: wrtc, initiator: true, gun: gun, GUN: GUN, axe: false }, hash, pair);
            // gundc_connections[hash].on("debug", console.log);
            gundc_connections[hash].on("connected", function(socket) {
                console.log("connected to agent");
                socket.on("disconnected", function() {
                    // console.log("socket disconnected");
                });
                
                socket.emit("get_pub", function(data) {
                    console.log("ssh-ed25519", buildKeyBase64(Buffer.from(data, "hex")));
                    startServer(data, socket);
                });

            });
            gundc_connections[hash].auth(function(pair, pass) {
                // console.log("CONNECTION_PAIR", pair);
                pass();
            })
        }
        

    }
    
    setup(com_keys);
    
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

process.on('exit', exitHandler.bind(null, { cleanup: true }));
process.on('SIGINT', exitHandler.bind(null, { exit: true }));
process.on('SIGUSR1', exitHandler.bind(null, { exit: true }));
process.on('SIGUSR2', exitHandler.bind(null, { exit: true }));
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

        stream.on('end', function() {
            // console.log('client disconnected');
        });

        stream.on('error', function(err) {
            console.log(err);
            // stream.write({ error: err.toString() });
        });

        var write = stream.write;

        //  https://tools.ietf.org/id/draft-miller-ssh-agent-01.html#messagenum
        var msgdata = [];
        var len = 0;
        var type = -1;
        stream
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


                try {
                    // console.log("req-type", type)
                    // console.log("data-in", Buffer.from(response))

                    var offset;
                    switch (type) {
                        
                        case helpers.PROTOCOL.SSH_AGENTC_REQUEST_RSA_IDENTITIES:
                            break;
                        case helpers.PROTOCOL.SSH2_AGENTC_REQUEST_IDENTITIES:
                            // console.log("SSH2_AGENTC_REQUEST_IDENTITIES", len, type, JSON.stringify(response))
                            
                            var key = Buffer.from(buildKeyBase64(Buffer.from(pub, "hex")), "base64");

                            // console.log("key", key.toString("utf8"))

                            var request = Buffer.alloc(4 + 1 + 4 + 1 + 4 + key.length + 4);

                            offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH2_AGENT_IDENTITIES_ANSWER);
                            helpers.ctype.wuint32(1, 'big', request, offset);
                            offset += 4;

                            offset = helpers._writeString(request, key, offset);
                            helpers.ctype.wuint32(0, 'big', request, offset);

                            stream.write(request);

                            // console.log("sent", request);
                            break;
                        case helpers.PROTOCOL.SSH2_AGENTC_SIGN_REQUEST:

                            offset = 0;

                            // console.log("SSH2_AGENTC_SIGN_REQUEST", len, type, JSON.stringify(response))

                            response = response.slice(5, len);

                            if (response.length) {
                                var blobkey = helpers._readString(response, offset);
                                offset += 4 + blobkey.len;
                                var indata = helpers._readString(response, offset);

                                // console.log("indata", JSON.stringify(indata.str));
                                // console.log("indata", indata.str.toString("utf8"));
                                // console.log("indata", indata.len);


                                socket.emit("sign_data", Array.from(indata.str), function(signature) {
                                    signature = Buffer.from(signature)
                                    // console.log("sig", signature);
                                    // console.log("sig", signature.length);
                                    // console.log("sig", JSON.stringify(signature.toString()));

                                    var kb_c = Buffer.from("ssh-ed25519");
                                    var resss = Buffer.alloc(4 + kb_c.length + 4 + signature.length)
                                    offset = 0;
                                    offset = helpers._writeString(resss, kb_c, offset);
                                    offset = helpers._writeString(resss, signature, offset);

                                    var request = Buffer.alloc(4 + 1 + 4 + resss.length);

                                    offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH2_AGENT_SIGN_RESPONSE);

                                    offset = helpers._writeString(request, resss, offset);
                                    stream.write(request);

                                    // console.log("sending response", request)
                                    // console.log("sending response", JSON.stringify(request))

                                });
                            }
                            break;

                        default:
                            
                            var request = Buffer.alloc(4 + 1 + 4 + 1 + 4);
                            
                            offset = helpers._writeHeader(request, helpers.PROTOCOL.SSH_AGENT_FAILURE);
                            
                            helpers.ctype.wuint32(0, 'big', request, offset);

                            stream.write(request);
                            console.log("fail");
                            break;
                    }


                }
                catch (e) { console.log(e) }
               
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
