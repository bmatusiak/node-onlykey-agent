var ctype = require("ctype");

var PROTOCOL = require("./AGENT-PROTOCOL.js");

function getCharCodes(s) {
    let charCodeArr = [];

    for (let i = 0; i < s.length; i++) {
        let code = s.charCodeAt(i);
        charCodeArr.push(code);
    }

    return charCodeArr;
}

function _newBuffer(buffers, additional) {
    //   assert.ok(buffers);

    var len = 5; // length + tag
    for (var i = 0; i < buffers.length; i++)
        len += 4 + buffers[i].length;

    if (additional)
        len += additional;

    return Buffer.alloc(len);
}


function _readString(buffer, offset) {
    // assert.ok(buffer);
    // assert.ok(offset !== undefined);

    var len = ctype.ruint32(buffer, 'big', offset);
    offset += 4;

    var str = Buffer.alloc(len);
    buffer.copy(str, 0, offset, offset + len);

    return { str: str, len: len };
}

function _writeString(request, buffer, offset) {
    // assert.ok(request);
    // assert.ok(buffer);
    // assert.ok(offset !== undefined);

    ctype.wuint32(buffer.length, 'big', request, offset);
    offset += 4;
    buffer.copy(request, offset);

    return offset + buffer.length;
}

function _readHeader(response, expect) {
    // assert.ok(response);

    var len = ctype.ruint32(response, 'big', 0);
    var type = ctype.ruint8(response, 'big', 4);

    return (expect === type ? len : -1);
}

function _writeHeader(request, tag) {
    ctype.wuint32(request.length - 4, 'big', request, 0);
    ctype.wuint8(tag, 'big', request, 4);
    return 5;
}


module.exports = {
    ctype: ctype,
    PROTOCOL: PROTOCOL,
    getCharCodes: getCharCodes,
    _newBuffer: _newBuffer,
    _readString: _readString,
    _writeString: _writeString,
    _readHeader: _readHeader,
    _writeHeader: _writeHeader
}