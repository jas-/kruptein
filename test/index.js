'use strict'

// Dependencies
const crypto = require('crypto')
const expect = require('expect.js')
const kruptein = require('../lib/kruptein.js')


// Inits
let hmac, ciphers = [], hashes = [],
    ciphers_tmp = [], hashes_tmp = [],
    encoding = ['binary'],
    tests = []


// Filter getCiphers()
ciphers = crypto.getCiphers().filter(cipher => {
  if (cipher.match(/^aes/i) && !cipher.match(/hmac|wrap/))
    return cipher
})

// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2|3|5]/i) && !hash.match(/rsa/i))
    return hash
})


// Build tests array's
ciphers.forEach(cipher => {
  hashes.forEach(hash => {
    encoding.forEach(encode => {
      tests.push(
        {
          'title': "{ algorithm: "+cipher+", hashing: "+hash+", encodeas: "+encode+" }",
          'options': {
            'algorithm': cipher,
            'hashing': hash,
            'encodeas': encode,
            'secret': 'squirrel'
          }
        }
      )
    })
  })
})


// Begin iterator
tests.forEach(test => {
  describe('kruptein: '+test.title, () => {
    let ct, pt

    // Init kruptein with the test options
    before(done => {
      done(kruptein.init(test.options))
    })


    it('Missing Secret', done => {
      let kruptein_copy = require('../lib/kruptein.js')

      test.options.secret = ''

      try {
        let tmp = kruptein_copy.init(test.options)
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

      if (test.options.algorithm.match(/ccm|gcm|ocb/))
        expect(ct).to.have.property('at')

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

      if (test.options.algorithm.match(/ccm|gcm|ocb/))
        expect(ct).to.have.property('at')

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

      expect(ct).to.have.property('ct')
      expect(ct).to.have.property('iv')
      expect(ct).to.have.property('hmac')

      if (!test.options.algorithm.match(/ccm|gcm|ocb/))
        done()

      expect(ct).to.have.property('at')

      ct.at = 'funky chicken'
      ct = JSON.stringify(ct)

      try {
        pt = kruptein.get(ct)
      } catch(err) {
        expect(err).to.match(/Unsupported state or unable to authenticate data/)
      }

      done()
    })

/*
    it('Authentication Tag Validation (option)', done => {
      try {
        ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
      } catch(err) {
        expect(err).to.be.null
      }

      expect(ct).to.have.property('ct')
      expect(ct).to.have.property('iv')
      expect(ct).to.have.property('hmac')

      if (!test.options.algorithm.match(/ccm|gcm|ocb/))
        done()

      expect(ct).to.have.property('at')

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

      if (!test.options.algorithm.match(/ccm|gcm|ocb/))
        done()

      expect(ct).to.have.property('at')

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

      if (!test.options.algorithm.match(/ccm|gcm|ocb/))
        done()

      expect(ct).to.have.property('at')

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

      if (test.options.algorithm.match(/ccm|gcm|ocb/))
        expect(ct).to.have.property('at')

      try {
        pt = kruptein.get(JSON.stringify(ct))
      } catch(err) {
        expect(err).to.be.null
      }

      expect(pt).to.match(/123, easy as ABC. ABC, easy as 123/)

      done()
    })
*/
  })
})

// fin