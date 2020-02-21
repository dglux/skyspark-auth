const AuthClientContext = require('./haystack-auth/auth/AuthClientContext');

window.skysparkAuth = function(url, user, password, callback, proxyHeader) {
  if (proxyHeader) {
    AuthClientContext.AUTH_HEADER = 'proxy-Authorization';
  }

  let a = new AuthClientContext(url, user, password, false);

  a.login(
    function(headers) {
      callback(headers['Authorization']);
    },
    function(msg) {
      console.log('Skyspark Authentication Failed: ' + msg);
    }
  );
};
