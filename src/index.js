const AuthClientContext = require('./haystack-auth/auth/AuthClientContext');

let a = new AuthClientContext('https://bip.ecovoxinc.com/api/miracosta/about', 'mcdglux', 'WQX8R-78LTC-PCN6G', false);

a.login(
  function(headers) {
    console.log('success: Authorization: ' + headers['Authorization']);
  },
  function(msg) {
    console.log('Failed: ' + msg);
  }
);
