'use strict'

const crypto = require('crypto')
const expect = require('expect.js')
const kruptein = require('../lib/kruptein.js')


let hmac, ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    encoding = ['binary']
    //encoding = ['base64', 'binary', 'hex']


const options = {
  secret: 'squirrel',
  debug: true
}


ciphers = crypto.getCiphers()
hashes = crypto.getHashes()


for (let cipher in ciphers) {
  if (!ciphers[cipher].match(/^aes/i) || ciphers[cipher].match(/hmac|wrap/))
    continue

  options.algorithm = ciphers[cipher]

  for (let hash in hashes) {
    if (!hashes[hash].match(/^sha[2|3|5]/i) || hashes[hash].match(/rsa/i))
      continue

    options.hashing = hashes[hash]

    for (let enc in encoding) {
      options.encodeas = encoding[enc]

      describe('kruptein: { algorithm: "'+options.algorithm+'", hashing: "'+options.hashing+'", encodeas: "'+options.encodeas+'" }', () => {
        let ct, pt, in_file="/var/tmp/test.pt", out_file="/var/tmp/test.ct"


        beforeEach(done =>  {
  console.log(ciphers[cipher])
          console.log(options.algorithm)
          kruptein.init(options)
        })


        it('Missing Secret', done => {
          let kruptein_copy = require('../lib/kruptein.js')

          options.secret = ''

          try {
            let tmp = kruptein_copy.init(options)
            expect(tmp).to.throw("Must supply a secret!")
          } catch(err) {
            expect(err).to.be.null
          }
          done()
        })


        it('Invalid Key Size', done => {
          let kruptein_tmp = require('../lib/kruptein.js')

          let opts = {
            key_size: 99999,
            secret: 'squirrel'
          }

          try {
            let tmp = kruptein_tmp.init(opts)
            expect(tmp).to.throw("Invalid key size!")
          } catch(err) {
            expect(err).to.be.null
          }

          try {
            ct = JSON.parse(kruptein_tmp.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }
          done()
        })


        it('Invalid IV Size', done => {
          let kruptein_tmp = require('../lib/kruptein.js')

          let opts = {
            iv_size: 99999,
            secret: 'squirrel'
          }

          try {
            let tmp = kruptein_tmp.init(opts)
            expect(tmp).to.throw("Invalid IV size!")
          } catch(err) {
            expect(err).to.be.null
          }

          try {
            ct = JSON.parse(kruptein_tmp.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }
          done()
        })


        it('Encrypt', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          expect(ct).to.have.property('ct')
          expect(ct).to.have.property('iv')
          expect(ct).to.have.property('hmac')

          if (options.algorithm.match(/ccm|gcm|ocb/))
            expect(ct).to.have.property('at')

          //console.log(JSON.stringify(ct))

          done()
        })


        it('HMAC Validation', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          expect(ct).to.have.property('ct')
          expect(ct).to.have.property('iv')
          expect(ct).to.have.property('hmac')

          ct.hmac = 'funky chicken'
          ct = JSON.stringify(ct)

          try {
            pt = kruptein.get(ct)
          } catch(err) {
            expect(err).to.equal('Encrypted session was tampered with!')
          }

          done()
        })


        it('Authentication Tag Validation', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          if (!ct.at)
            return done()
    
          expect(ct).to.have.property('ct')
          expect(ct).to.have.property('iv')
          expect(ct).to.have.property('hmac')

          ct.at = 'funky chicken'
          ct = JSON.stringify(ct)

          try {
            pt = kruptein.get(ct)
          } catch(err) {
            expect(err).to.match(/Unsupported state or unable to authenticate data/)
          }
          done()
        })


        it('Authentication Tag Validation (option)', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          if (!ct.at)
            return done()
    
          expect(ct).to.have.property('ct')
          expect(ct).to.have.property('iv')
          expect(ct).to.have.property('hmac')

          let opts = {at: ct.at}
          ct = JSON.stringify(ct)

          try {
            pt = kruptein.get(ct, opts)
          } catch(err) {
            expect(err).to.be.null
          }

          expect(pt).to.match(/123, easy as ABC. ABC, easy as 123/)

          done()
        })


        it('Additional Authentication Data Validation', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          expect(ct).to.have.property('ct')
          expect(ct).to.have.property('iv')
          expect(ct).to.have.property('hmac')

          if (!ct.aad)
            return done()
    
          ct.aad = 'funky chicken'
          ct = JSON.stringify(ct)

          try {
            pt = kruptein.get(ct)
          } catch(err) {
            expect(err).to.match(/Unsupported state or unable to authenticate data/)
          }
          done()
        })


        it('Additional Authentication Data Validation (option)', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          if (!ct.aad)
            return done()
    
          expect(ct).to.have.property('ct')
          expect(ct).to.have.property('iv')
          expect(ct).to.have.property('hmac')

          let opts = {aad: ct.aad}
          ct = JSON.stringify(ct)

          try {
            pt = kruptein.get(ct, opts)
          } catch(err) {
            expect(err).to.be.null
          }

          expect(pt).to.match(/123, easy as ABC. ABC, easy as 123/)

          done()
        })


        it('Decrypt', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          expect(ct).to.have.property('ct')
          expect(ct).to.have.property('iv')
          expect(ct).to.have.property('hmac')

          try {
            pt = kruptein.get(JSON.stringify(ct))
          } catch(err) {
            expect(err).to.be.null
          }

          expect(pt).to.match(/123, easy as ABC. ABC, easy as 123/)

          done()
        })
      })
    }
  }
}
