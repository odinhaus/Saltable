var curve25519xsalsa20poly1305 = {};
/* constants */
curve25519xsalsa20poly1305.PUBLICKEYBYTES = 32;
curve25519xsalsa20poly1305.SECRETKEYBYTES = 32;
curve25519xsalsa20poly1305.BEFORENMBYTES = 32;
curve25519xsalsa20poly1305.NONCEBYTES = 24;
curve25519xsalsa20poly1305.ZEROBYTES = 32;
curve25519xsalsa20poly1305.BOXZEROBYTES = 16;

function getStringBytes(str) {
	var b = new Array(str.length);
	for (var i = 0; i < str.length; i++) b[i] = str.charCodeAt(i);
	return b;
}

//Never written to
curve25519xsalsa20poly1305.sigma = getStringBytes('expand 32-byte k');

curve25519xsalsa20poly1305.crypto_box_beforenm = function(k, pk, sk) { //Byte* k, Byte* pk, Byte* sk
	var s = ZeroArray(32);
	curve25519.crypto_scalarmult(s, sk, pk);
	return hsalsa20.crypto_core(k, null, s, sigma); //k, np, sp, sigmap
}
curve25519xsalsa20poly1305.crypto_box_afternm = function(c, m, mlen, n, k) { //Byte* c, Byte* m, UInt64 mlen, Byte* n, Byte* k) {
	return xsalsa20poly1305.crypto_secretbox(c, m, mlen, n, k);
}
curve25519xsalsa20poly1305.crypto_box_open_afternm = function(m, c, clen, n, k) { //Byte* m, Byte* c, UInt64 clen, Byte* n, Byte* k) {
	return xsalsa20poly1305.crypto_secretbox_open(m, c, clen, n, k);
}
curve25519xsalsa20poly1305.crypto_box = function(c, m, mlen, n, pk, sk) { //Byte* c, Byte* m, UInt64 mlen, Byte* n, Byte* pk, Byte* sk
	var k = ZeroArray(this.BEFORENMBYTES);
	crypto_box_beforenm(k, pk, sk);
	return crypto_box_afternm(c, m, mlen, n, k);
}
curve25519xsalsa20poly1305.crypto_box_open = function(m, c, clen, n, pk, sk) { //Byte* m, Byte* c, UInt64 clen, Byte* n, Byte* pk, Byte* sk
	var k = ZeroArray(this.BEFORENMBYTES);
	crypto_box_beforenm(k, pk, sk);
	return crypto_box_open_afternm(m, c, clen, n, k);
}
/* static array based methods */
curve25519xsalsa20poly1305.crypto_box_keypair = function(pk, sk) { //out Byte[32] pk, out Byte[32] sk
	randombytes.generate(sk); //randombytes(sk, 32);
	return curve25519.crypto_scalarmult_base(pk, sk);
}

var randombytes = {};
randombytes.generate = function(arr) {
	for (var i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
}