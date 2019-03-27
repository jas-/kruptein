'use strict'

const fs = require('fs')
const crypto = require('crypto')
const expect = require('expect.js')
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
  if (!ciphers[cipher].match(/^aes/i) || ciphers[cipher].match(/hmac|wrap/))
    continue

  options.algorithm = ciphers[cipher]

  for (let hash in hashes) {
    if (!hashes[hash].match(/^sha[2|3|5]/i) || hashes[hash].match(/rsa/i))
      continue

    options.hashing = hashes[hash]

    for (let enc in encoding) {
      options.encodeas = encoding[enc]

      kruptein.init(options)

      describe('kruptein: { algorithm: "'+options.algorithm+'", hashing: "'+options.hashing+'", encodeas: "'+options.encodeas+'" }', () => {
        let ct, pt, in_file="/var/tmp/test.pt", out_file="/var/tmp/test.ct"


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
          done()
        })


        it('Encrypt File', done => {
          fs.writeFile(in_file, '123, easy as ABC. ABC, easy as 123', (err) => {
            expect(err).to.be.null
          })
          expect(in_file).to.exist

          fs.readFile(in_file, (err, data) => {
            expect(err).to.be.null
              
            fs.writeFile(out_file, kruptein.set(data), (err) => {
              expect(err).to.be.null
            })
          })

          expect(out_file).to.exist

          fs.exists(in_file, (err) => {
            expect(err).to.be.null

            fs.unlink(in_file, (err) => {
              expect(err).to.be.null
            })
          })

          expect(in_file).to.not.exist

          done()
        })


        it('HMAC Validation', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          ct.hmac = 'funky chicken'
          ct = JSON.stringify(ct)

          try {
            pt = kruptein.get(ct)
          } catch(err) {
            expect(err).to.equal('Encrypted session was tampered with!')
          }

          done()
        })


        it('HMAC Validation File', done => {
          fs.readFile(out_file, (err, data) => {
            expect(err).to.be.null

            try {
              data = JSON.parse(data)
            } catch(err) {
              expect(err).to.be.null
            }
console.log(data)
            data.hmac = 'funky chicken'
            data = JSON.stringify(data)

            try {
              pt = kruptein.get(data)
            } catch(err) {
              expect(err).to.equal('Encrypted session was tampered with!')
            }
          })

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
    
          ct.at = 'funky chicken'
          ct = JSON.stringify(ct)

          try {
            pt = kruptein.get(ct)
          } catch(err) {
            expect(err).to.match(/Unsupported state or unable to authenticate data/)
          }
          done()
        })


        it('Authentication Tag Validation File', done => {
          fs.readFile(out_file, (err, data) => {
            expect(err).to.be.null

            try {
              data = JSON.parse(data)
            } catch(err) {
              expect(err).to.be.null
            }

            if (ct.at) {
              data.at = 'funky chicken'
              data = JSON.stringify(data)
            } else {
              JSON.stringify(data)
            }

            try {
              pt = kruptein.get(data)
            } catch(err) {
              expect(err).to.match(/Unsupported state or unable to authenticate data/)
            }
          })

          done()
        })


        it('Additional Authentication Data Validation', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

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


        it('Additional Authentication Data Validation File', done => {
          fs.readFile(out_file, (err, data) => {
            expect(err).to.be.null

            try {
              data = JSON.parse(data)
            } catch(err) {
              expect(err).to.be.null
            }

            if (ct.aad) {
              data.aad = 'funky chicken'
              data = JSON.stringify(data)
            } else {
              JSON.stringify(data)
            }

            try {
              pt = kruptein.get(data)
            } catch(err) {
              expect(err).to.match(/Unsupported state or unable to authenticate data/)
            }
          })

          done()
        })


        it('Decrypt', done => {
          try {
            ct = JSON.parse(kruptein.set('123, easy as ABC. ABC, easy as 123'))
          } catch(err) {
            expect(err).to.be.null
          }

          try {
            pt = kruptein.get(JSON.stringify(ct))
          } catch(err) {
            expect(err).to.be.null
          }

          expect(pt).to.match(/123, easy as ABC. ABC, easy as 123/)

          done()
        })


        it('Decrypt File', done => {
          fs.readFile(out_file, (err, data) => {
            expect(err).to.be.null

            try {
              pt = kruptein.get(data)
            } catch(err) {
              expect(err).to.be.null
            }

            pt = Buffer.from(JSON.parse(pt).data).toString('utf8')

            expect(pt).to.match(/123, easy as ABC. ABC, easy as 123/)
          })

          fs.exists(out_file, (err) => {
            expect(err).to.be.null

            fs.unlink(out_file, (err) => {
              expect(err).to.be.null
            })
          })

          expect(out_file).to.not.exist

          done()
        })
      })
    }
  }
}
