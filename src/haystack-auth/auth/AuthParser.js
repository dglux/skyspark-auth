//
// Copyright (c) 2017, SkyFoundry LLC
// Licensed under the Academic Free License version 3.0
//
// History:
//   5 July 2017 Hank Weber Creation
//

AuthParser = function(header)
{
  this.buf  = header;
  this.pos  = -2;
  this.cur  = -1;
  this.peek = -1;
  this.reset(0);

  this.SP    = " ".charCodeAt(0);
  this.HTAB  = "\t".charCodeAt(0);
  this.COMMA = ",".charCodeAt(0);
  this.EQ    = "=".charCodeAt(0);
  this.DQUOT = '"'.charCodeAt(0);
  this.EOF   = -1;
}

module.exports = AuthParser;

AuthParser.prototype.nextScheme = function()
{
  if (this.eof()) return null;
  if (this.pos > 0) this.commaOws();

  var AuthScheme = 
  {
    name: null,
    params: {},
    param: function(name) 
    {
      var val = null;
      var params = this.params;
      Object.keys(params).forEach(function (key) 
      {
        if (key.toLowerCase() == name.toLowerCase()) val = params[key];
      });
      return val;
    }
  };
  var scheme = Object.create(AuthScheme);
  scheme.name = this.parseToken([this.SP, this.COMMA, this.EOF]).toLowerCase();
  if (this.cur != this.SP) return scheme;

  while (this.cur == this.SP) this.consume();

  scheme.params = this.parseAuthParams();
  return scheme;
  /*
   var start = this.pos;
   while (true)
   {
   start = this.pos;
   if (this.eof()) break;
   if (Object.keys(scheme.params).length > 0) this.commaOws();
   if (!this.parseAuthParam(scheme.params)) { this.reset(start); break; }
   this.ows();
   }
   return scheme;
   */
}

AuthParser.prototype.parseToken = function(terms)
{
  var start = this.pos;
  while (true)
  {
    if (this.eof())
    {
      if (terms.indexOf(this.EOF) >= 0) break;
      throw "Unexpected <eof>: " + this.buf;
    }
    if (terms.indexOf(this.cur) >= 0) break;
    this.consume();
  }
  return this.buf.substring(start, this.pos);
}

AuthParser.prototype.parseAuthParams = function()
{
  var params = {};
  var start = this.pos;
  while (true)
  {
    start = this.pos;
    if (this.eof()) break;
    if (Object.keys(params).length > 0) this.commaOws();
    if (!this.parseAuthParam(params)) { this.reset(start); break; }
    this.ows();
  }
  return params;
}

AuthParser.prototype.parseAuthParam = function(params)
{
  if (this.eof()) return false;

  var start = this.pos;
  var key = this.parseToken([this.SP, this.HTAB, this.EQ, this.COMMA, this.EOF]).toLowerCase();
  this.ows();
  if (this.cur != this.EQ)
  {
    // backtrack
    this.reset(start);
    return false;
  }
  this.consume();
  this.ows();
  var val = this.cur == this.DQUOT ? this.parseQuotedString() : this.parseToken([this.SP, this.HTAB, this.COMMA, this.EOF]);
  this.ows();
  params[key] = val;
  return true;
}

AuthParser.prototype.parseQuotedString = function()
{
  var start = this.pos;
  if (this.cur != this.DQUOT) throw "Expected '\"' at pos " + this.pos;
  this.consume();
  while(true)
  {
    if (this.eof()) throw "Unterminated quoted-string starting at " + this.pos;
    if (this.cur == this.DQUOT) { this.consume(); break; }
    if (this.cur == this.ESC && this.peek == this.DQUOT) { this.consume(); this.consume(); }
    else this.consume();
  }
  var quoted = this.buf.substring(start, this.pos);
  if (quoted.length < 2 || quoted[0] != '"' || quoted[quoted.length-1] != '"')
    throw "Not a quoted string: " + quoted;
  return quoted.substring(1, quoted.length-1).replace("\\\"", '"');
}

AuthParser.prototype.commaOws = function()
{
  if (this.cur != this.COMMA) throw "Expected ',': " + buf.substring(0, this.pos);
  this.consume();
  this.ows();
}

AuthParser.prototype.ows = function()
{
  while(this.isOws()) this.consume();
}

AuthParser.prototype.isOws = function()
{
  return this.cur == this.SP || this.cur == this.HTAB;
}

AuthParser.prototype.reset = function(pos)
{
  this.pos = pos - 2;
  this.consume();
  this.consume();
}

AuthParser.prototype.consume = function()
{
  this.cur = this.peek;
  this.pos++;
  if (this.pos+1 < this.buf.length)
    this.peek = this.buf.charCodeAt(this.pos+1);
  else
    this.peek = -1;
  if (this.pos > this.buf.length) pos = this.buf.length;
}

AuthParser.prototype.eof = function()
{
  return this.cur == this.EOF;
}