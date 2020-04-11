"use strict";

const crypto = require('crypto');

let secret = "squirrel", kruptein,
    ciphers = [], hashes = [],
    encoding = ['binary', 'hex', 'base64', 'utf16le'],
    phrases = [
      "Operation mincemeat was an example of deception",
      "Krimbi i operacionit ishte një shembull mashtrimi",
      "ye’opirēshini mīnī-serashi yemataleli misalē neberi",
      "كانت عملية اللحم المفروم مثالا للخداع",
      "Գործողության աղանդը խաբեության օրինակ էր",
      "অপারেশন মিনসমেট প্রতারণার উদাহরণ ছিল",
      "ऑपरेशन कीमाईट धोखे का एक उदाहरण था",
      "A darált sertéshús volt a megtévesztés egyik példája",
      "Aðgerð kjötkjöt var dæmi um blekkingar",
      "Sampla de mheabhlaireacht ab ea mincemeat oibríochta",
      "L'operazione carne tritata era un esempio di inganno",
      "Picadinho de operação foi um exemplo de engano",
      "ਓਪਰੇਸ਼ਨ ਮੀਨਮੀਟ ਧੋਖਾ ਖਾਣ ਦੀ ਇੱਕ ਉਦਾਹਰਣ ਸੀ",
      "Operațiunea mincemeat a fost un exemplu de înșelăciune",
      "Операционный фарш был примером обмана",
      "Операција мљевеног меса била је пример обмане",
      "Chiến dịch mincemeat là một ví dụ về sự lừa dối",
      "Mincemeat-ийг ажиллуулах нь хууран мэхлэх жишээ байв",
      "Operation Hackfleisch war ein Beispiel für Täuschung",
      "ოპერაციის მინერალმა მოტყუების მაგალითი იყო", 
    ];


const options = {
  use_scrypt: true
};


// Filter getCiphers()
ciphers = crypto.getCiphers().filter(cipher => {
  if (cipher.match(/^aes/i) && !cipher.match(/hmac|wrap|ccm|ecb/))
    return cipher;
});


// Filter getHashes()
hashes = crypto.getHashes().filter(hash => {
  if (hash.match(/^sha[2-5]/i) && !hash.match(/rsa/i))
    return hash;
});

for (let cipher in ciphers) {
  options.algorithm = ciphers[cipher];

  for (let hash in hashes) {
    options.hashing = hashes[hash];

    for (let enc in encoding) {
      options.encodeas = encoding[enc];

      kruptein = require("../index.js")(options);

      console.log('kruptein: { algorithm: "'+options.algorithm+'", hashing: "'+options.hashing+'", encodeas: "'+options.encodeas+'" }');
      let ct, pt;

      for (let phrase in phrases) {

        console.log(phrases[phrase])

        kruptein.set(secret, phrases[phrase], (err, res) => {
          if (err)
            console.log(err);

          ct = res;
        });

        console.log(JSON.stringify(ct));

        kruptein.get(secret, ct, (err, res) => {
          if (err)
            console.log(err);

          pt = res;
        });

        console.log(pt);
        console.log("");
      }
    }
  }
}

