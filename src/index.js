const AuthClientContext = require('./haystack-auth/auth/AuthClientContext');
const cookie = require('cookie');

window.skysparkAuth = function(url, user, password, callback, proxyHeader) {
  if (proxyHeader) {
    AuthClientContext.useProxy();
  }

  let a = new AuthClientContext(url, user, password, false);

  a.login(
    function(headers) {
      let auth = headers[AuthClientContext.getAuthHeader()] || headers['Authentication-Info'];
      let parts = auth && auth.split(/[= ,]/g);
      if (parts) {
        let authTokenPos = parts.indexOf('authToken');
        if (authTokenPos > -1) {
          callback(parts[authTokenPos + 1]);
          return;
        }
      }
      console.log('Skyspark Authentication, Invalid Token : ' + headers);
    },
    function(msg) {
      if (msg.includes('Hello failed with error code: 200')) {
        let map = cookie.parse(document.cookie);
        for (let key in map) {
          if (key.startsWith('prx-skyarc-auth')) {
            callback(map[key]);
            return;
          }
        }
      }
      console.log('Skyspark Authentication Failed: ' + msg);
    }
  );
};
