'use strict'

const crypto = require('crypto')
const kruptein = require('../lib/kruptein.js')

let hmac, ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    encoding = ['binary']
    //encoding = ['base64', 'binary', 'hex']

const options = {
  secret: 'squirrel'
}

ciphers = crypto.getCiphers()
hashes = crypto.getHashes()

for (let cipher in ciphers) {
  if (!ciphers[cipher].match(/^aes/i) || ciphers[cipher].match(/hmac|ccm|wrap/))
    continue

  options.algorithm = ciphers[cipher]

  for (let hash in hashes) {
    if (!hashes[hash].match(/^sha[2|3|5]/i) || hashes[hash].match(/rsa/i))
      continue

    options.hashing = hashes[hash]

    for (let enc in encoding) {
      options.encodeas = encoding[enc]

      kruptein.init(options)

      console.log('kruptein: { algorithm: "'+options.algorithm+'", hashing: "'+options.hashing+'", encodeas: "'+options.encodeas+'" }')
      let ct, pt

      try {
        ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
      } catch(err) {
        console.log(err)
      }

      //console.log(ct)

      try {
        pt = kruptein.get(JSON.stringify(ct))
      } catch(err) {
        console.log(err)
      }

      console.log(pt)
    }
  }
}