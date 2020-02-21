//
// Copyright (c) 2017, SkyFoundry LLC
// Licensed under the Academic Free License version 3.0
//
// History:
//   5 July 2017 Hank Weber Creation
//

var MyCrypto = require('../crypto/MyCrypto'),
  http = require('http'),
  url = require('url'),
  https = require('https'),
  MyParser = require('./AuthParser');

/**
 * Creates AuthClientContext object which contains user information to be authenticated.
 * @constructor
 * @param {String} uri - The uri to the haystack
 * @param {String} user - The username to login with
 * @param {String} pass - The password for the desired user
 * @param {Boolean} reject - Sets the value of "rejectUnauthorized" header when connecting through https
 */
function AuthClientContext(uri, user, pass, reject) {
    this.curUri = url.parse(uri);
    this.host = this.curUri.hostname;
    this.path = this.curUri.pathname;
    this.port = this.curUri.port;
    this.user = user;
    this.pass = pass;
    this.headers = new Object();
    this.reject = reject;
}

/**
 * Attempts to login with the information of the AuthClientContext object
 *
 * @param {Function} onSuccess - defines the behavior upon a successfull login, it is passed an object containing the Authorization header.
 * @param {Function} onFail = defines the behavior upon a failed login, it is passed a string with a failure message
 */
AuthClientContext.prototype.login = function(onSuccess, onFail)
{
    this.onSuccess = onSuccess;
    this.onFail = onFail;
    var crypto = MyCrypto.crypto;
    var cur = this;
    if(!(typeof(onSuccess) == "function") || !(typeof(onFail) == "function"))
    {
        throw Error("onSuccess or onFail is not a proper function.");
        return;
    }
    var username = this.user;
    var password = this.pass;
    var u64 = this.str2b64uriUtf8(username);
    var authInfo = cur.prepare({"Authorization":'hello username=' + u64});
    this.sendReq(authInfo, 'GET', 'about', function (callback)
    {
        if (callback.statusCode == 303) //must redirect request
        {
            cur.curUri = url.parse(callback.headers["location"]);
            cur.host = cur.curUri.hostname;
            cur.port = cur.curUri.port;
            cur.path = cur.curUri.path.substring(0, cur.curUri.path.lastIndexOf("/"));
            cur.sendReq(authInfo, 'GET', 'about', function(callback2)
            {
                after(callback2);
            });
        }
        else
        {
            after(callback);
        }
    });

    var after = function (func)
    {
        if (func.statusCode != 401)
        {
            return cur.onFail("Hello failed with error code: " + func.statusCode);;
        }
        cur.scheme = cur.parseWwwAuth(func.headers)
        try
        {
            if ("scram" == cur.scheme.name)
                cur.scram(username, password, cur.scheme);
            else
                throw "Unsupported auth scheme: " + scheme.toLowerCase();
        }
        catch (e)
        {
            return cur.onFail(e.toString());
        }
    }
};

/**
 * Prepares the authorization header for a request, checks to see if the current AuthClientContext has a token already, otherwise uses the parameter.
 *
 * @param {Object} htp - the headers to prepare for the request.
 * @returns {Object} hts - the prepared headers to send with the request.
 */
AuthClientContext.prototype.prepare = function(htp)
{
    if(htp == null) htp = new Object();
    var hts = htp;
    if(Object.keys(this.headers).length > 0)
    {
        for(var key in this.headers)
        {
            if(this.headers.hasOwnProperty(key))
            {
                hts[key] = this.headers[key];
            }
        }
    }
    return hts
};

/**
 * Builds the request from the given arguments and sends it.
 *
 * @param {Object} reqHeaders - Object containing name-value pairs of request headers
 * @param {string} c_method - The connection method
 * @param {String} extension - The password for the desired user
 * @param {Function} func - The function returned by the request
 */
AuthClientContext.prototype.sendReq = function(reqHeaders, c_method, extension, func)
{
	var options = {host: this.host, port: this.port, path: this.path+'/'+extension, headers: reqHeaders, method: c_method};
  if(this.curUri.protocol.startsWith("https")){
    options["rejectUnauthorized"] = this.reject;
    options["port"] = this.port;
    https.request(options, func).end();
  }
  else if(this.curUri.protocol.startsWith("http"))
  {
    http.request(options, func).end();
  }
  else
  {
    this.onFail("Unrecognized protocol for request.");
  }
};


AuthClientContext.prototype.str2b64uriUtf8 = function(s)
{
  var crypto = MyCrypto.crypto;
  return crypto.rstr2b64uri(crypto.str2rstr_utf8(s));
};

AuthClientContext.prototype.toQuotedStr = function(s)
{
  return '"' + s.replace('"', '\\"') + '"';
};

AuthClientContext.prototype.parseWwwAuth = function (resp)
{
  var wwwAuth = resp["WWW-Authenticate".toLowerCase()];
  var parser = new MyParser(wwwAuth);
  return parser.nextScheme();
};

AuthClientContext.prototype.scram = function (username, password, hello)
{
  var cur = this;
  var crypto = MyCrypto.crypto;
  var hashSpec = this.hashSpec(hello.params["hash"]);
  var hash = hashSpec["hash"];
  var keyBits = hashSpec["bits"];

  var gs2_header = "n,,";
  var c_nonce = crypto.nonce(24);
  var c1_bare = "n=" + username + ",r=" + c_nonce;
  var c1_msg = gs2_header + c1_bare;
  var c1_data = crypto.rstr2b64uri(c1_msg);

  var decode = function (s)
  {
    var data = {};
    s.split(',').forEach(function (tok)
    {
      var n = tok.indexOf('=');
      if (n > 0)
      {
        data[tok.substring(0, n)] = tok.substring(n + 1);
      }
    });
    return data;
  };

  var doFinal = function (scheme1)
  {
    var s1_msg = Buffer.from(scheme1.param("data"), 'base64').toString('utf8');
    var s1Data = decode(s1_msg);
    var cbind_input = gs2_header;
    var channel_binding = "c=" + crypto.rstr2b64(cbind_input);
    var nonce = "r=" + s1Data["r"];
    var c2_no_proof = channel_binding + "," + nonce;

    // construct proof
    var salt = Buffer.from(s1Data["s"], 'base64').toString('binary');
    var iterations = parseInt(s1Data["i"]);
    var saltedPassword = crypto.pbkdf2_hmac_sha256(password, salt, iterations, keyBits / 8);
    var clientKey = hash("Client Key", saltedPassword);
    var storedKey = hash(clientKey);
    var authMsg = c1_bare + "," + s1_msg + "," + c2_no_proof;
    var clientSig = hash(authMsg, storedKey);

    var proof = crypto.rstr2b64(crypto.xor(clientKey, clientSig));
    var c2_msg = c2_no_proof + ",p=" + proof;
    var c2_data = crypto.rstr2b64uri(c2_msg);
    var header = '' + hello.name + ' data=' + c2_data;
    var tok = scheme1.params["handshaketoken"];
    if (tok != null) header += ", handshakeToken=" + tok;
    var authInfo = cur.prepare({"Authorization":header});
    cur.sendReq(authInfo, 'GET', 'about', function (callback)
    {
      if (callback.statusCode != 200)
      {
        cur.onFail(cur.localeBadCreds);
      }
      else
      {
        this.pass = null;
        cur.headers["Authorization"] = "bearer " + callback.headers["authentication-info"].split(",")[0];
        cur.onSuccess(cur.headers);
      }
    });
  };

  var header = hello.name + " data=" + c1_data;
  var tok = hello.params["handshaketoken"];
  if (tok != null) header += ", handshakeToken=" + tok;

  //var cur = this;
  var authInfo = cur.prepare({"Authorization":header});
  cur.sendReq(authInfo, 'GET', 'about', function (callback)
  {
    if (callback.statusCode != 401)
    {
      cur.onFail(cur.localeBadCreds);
    }
    else
    {
      doFinal(cur.parseWwwAuth(callback.headers));
    }
  });
};

AuthClientContext.prototype.hashSpec = function (hashFunc)
{
  var crypto = MyCrypto.crypto;
  var spec = {};
  switch (hashFunc.toLowerCase())
  {
  case "sha-1": spec["hash"] = crypto.sha1; spec["bits"] = 160; break;
  case "sha-256": spec["hash"] = crypto.sha256; spec["bits"] = 256; break;
  default: throw "Unsupported hashFunc: " + hashFunc;
  }
  return spec;
};

AuthClientContext.prototype.hashPwd = function (username, password, scheme)
{
  var crypto = MyCrypto.crypto;
  var algorithm = scheme.name;
  var hashFunc = scheme.param("hash");
  var hashSpec = this.hashSpec(hashFunc);
  var salt = crypto.b64uri2rstr(scheme.param("salt"));
  if ("hmac" == algorithm)
  {
    salt = crypto.rstr2b64(salt);
    return hashSpec["hash"](username + ":" + salt, password);
  }
  if ("scram" == algorithm)
  {
    if (hashFunc != "SHA-256") throw "Unsupported hash func for pbkdf2 " + hashFunc;
    var iterations = parseInt(scheme.param("c"));
    var dkLen = hashSpec["bits"] / 8; // convert bits to bytes
    var saltedPassword = crypto.pbkdf2_hmac_sha256(password, salt, iterations, dkLen);
    return saltedPassword;
  }
  else throw "Unsupported algorithm: " + algorithm;
};

module.exports = AuthClientContext;
