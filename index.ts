import fetch from 'node-fetch';

function findNext(arr: string[], key: string) {
  let index = arr.indexOf(key);
  if (index >= 0) {
    return arr[index + 1];
  }
  return null;
}

async function main() {
  /*
  const response = await fetch(url, {
    method: 'POST', // *GET, POST, PUT, DELETE, etc.
    mode: 'cors', // no-cors, *cors, same-origin
    cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
    credentials: 'same-origin', // include, *same-origin, omit
    headers: {
      'Content-Type': 'application/json'
      // 'Content-Type': 'application/x-www-form-urlencoded',
    },
    redirect: 'follow', // manual, *follow, error
    referrerPolicy: 'no-referrer', // no-referrer, *client
    body: JSON.stringify(data) // body data type must match "Content-Type" header
  });
  return await response.json(); // parses JSON response into native JavaScript objects
 */
  let response = await fetch('https://bip.ecovoxinc.com/api/miracosta/about', {
    headers: {
      authorization: 'HELLO username=bWNkZ2x1eA'
    }
  });

  let auth0 = response.headers.get('www-authenticate');
  let parts = auth0.split(/[ =,]/g);
  let handshakeToken = findNext(parts, 'handshakeToken');
  console.log(handshakeToken);
  let handshakeTokenBuf = Buffer.from(handshakeToken, 'base64');
  console.log(handshakeTokenBuf);

  let response1 = await fetch('https://bip.ecovoxinc.com/api/miracosta/about', {
    headers: {
      authorization: `SCRAM handshakeToken=${handshakeToken}, data=biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8K`
    }
  });
  console.log(response1.headers)
}

main();
