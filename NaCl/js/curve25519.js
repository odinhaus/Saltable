var curve25519 = {};
curve25519.CRYPTO_BYTES = 32;
curve25519.CRYPTO_SCALARBYTES = 32;

//Never written to (both)
curve25519.basev = [ 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]; //[32] = {9};
curve25519.minusp = [ 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128 ];

curve25519.crypto_scalarmult_base = function(q, n) { //Byte* q, Byte* n
	return this.crypto_scalarmult(q, n, this.basev);
}
curve25519.add = function(outv, a, b, ooff, aoff, boff) { //UInt32* outv, UInt32* a, UInt32* b
	var u = 0;
	for (var j = 0; j < 31; ++j) { u += a[j + aoff] + b[j + boff]; outv[j + ooff] = u & 255; u >>= 8; }
	u += a[31 + aoff] + b[31 + boff]; outv[31 + ooff] = u;
}
curve25519.sub = function(outv, a, b, ooff, aoff, boff) {//UInt32* outv, UInt32[] a, UInt32* b
	var  u = 218;
	for (var j = 0; j < 31; ++j) {
		u += a[j + aoff] + 65280 - b[j + boff];
		outv[j + ooff] = u & 255;
		u >>= 8;
	}
	u += a[31 + aoff] - b[31 + boff];
	outv[31 + ooff] = u;
}
curve25519.squeeze = function(a, aoff) { //a[32]
	var u = 0;
	for (var j = 0; j < 31; ++j) { u += a[j + aoff]; a[j + aoff] = u & 255; u >>= 8; }
	u += a[31 + aoff]; a[31 + aoff] = u & 127;
	u = 19 * (u >> 7);
	for (var j = 0; j < 31; ++j) { u += a[j + aoff]; a[j + aoff] = u & 255; u >>= 8; }
	u += a[31 + aoff]; a[31 + aoff] = u;
}
curve25519.freeze = function(a, aoff) {
	var aorig = new Array(32);
	for (var j = 0; j < 32; ++j) aorig[j] = a[j + aoff];
	this.add(a, a, this.minusp, aoff, aoff, 0);
	var negative = (-((a[31 + aoff] >> 7) & 1)); //cast to (UInt32)
	for (var j = 0; j < 32; ++j) a[j + aoff] ^= negative & (aorig[j] ^ a[j + aoff]);
}
curve25519.mult = function(outv, a, b, ooff, aoff, boff) {
	var  j;
	for (var i = 0; i < 32; ++i) {
		var u = 0;
		for (j = 0; j <= i; ++j) u += a[j + aoff] * b[i - j + boff];
		for (j = i + 1; j < 32; ++j) u += 38 * a[j + aoff] * b[i + 32 - j + boff];
		outv[i + ooff] = u;
	}
	this.squeeze(outv, ooff);
}
curve25519.mult121665 = function(outv, a, ooff, aoff) { //outv[32], a[32]
	var j;
	var u = 0;
	for (j = 0; j < 31; ++j) { u += 121665 * a[j + aoff]; outv[j + ooff] = u & 255; u >>= 8; }
	u += 121665 * a[31 + aoff]; outv[31 + ooff] = u & 127;
	u = 19 * (u >> 7);
	for (j = 0; j < 31; ++j) { u += outv[j + ooff]; outv[j + ooff] = u & 255; u >>= 8; }
	u += outv[j + ooff]; outv[j + ooff] = u;
}
curve25519.square = function(outv, a, ooff, aoff) {
	var  j;
	for (var i = 0; i < 32; ++i) {
		var u = 0;
		for (j = 0; j < i - j; ++j) u += a[j + aoff] * a[i - j + aoff];
		for (j = i + 1; j < i + 32 - j; ++j) u += 38 * a[j + aoff] * a[i + 32 - j + aoff];
		u *= 2;
		if ((i & 1) == 0) {
			u += a[i / 2 + aoff] * a[i / 2 + aoff];
			u += 38 * a[i / 2 + 16 + aoff] * a[i / 2 + 16 + aoff];
		}
		outv[i + ooff] = u;
	}
	this.squeeze(outv, ooff);
}
curve25519.select = function(p, q, r, s, b) { //p[64], q[64], r[64], s[64]
	var bminus1 = b - 1;
	for (var j = 0; j < 64; ++j) {
		var t = bminus1 & (r[j] ^ s[j]);
		p[j] = s[j] ^ t;
		q[j] = r[j] ^ t;
	}
}
curve25519.mainloop = function(work, e) { //work[64], e[32]
	var xzm1 = ZeroArray(64);
	var xzm = ZeroArray(64);
	var xzmb = ZeroArray(64);
	var xzm1b = ZeroArray(64);
	var xznb = ZeroArray(64);
	var xzn1b = ZeroArray(64);
	var a0 = ZeroArray(64);
	var a1 = ZeroArray(64);
	var b0 = ZeroArray(64);
	var b1 = ZeroArray(64);
	var c1 = ZeroArray(64);
	var r = ZeroArray(32);
	var s = ZeroArray(32);
	var t = ZeroArray(32);
	var u = ZeroArray(32);

	for (var j = 0; j < 32; ++j) xzm1[j] = work[j];
	xzm1[32] = 1;
	for (var j = 33; j < 64; ++j) xzm1[j] = 0;

	xzm[0] = 1;
	for (var j = 1; j < 64; ++j) xzm[j] = 0;

	for (var pos = 254; pos >= 0; --pos) {
		var b = (e[Math.floor(pos / 8)] >> (pos & 7)); //cast to (UInt32)
		b &= 1;
		this.select(xzmb, xzm1b, xzm, xzm1, b);
		this.add(a0, xzmb, xzmb, 0, 0, 32);
		this.sub(a0, xzmb, xzmb, 32, 0, 32);
		this.add(a1, xzm1b, xzm1b, 0, 0, 32);
		this.sub(a1, xzm1b, xzm1b, 32, 0, 32);
		this.square(b0, a0, 0, 0);
		this.square(b0, a0, 32, 32);
		this.mult(b1, a1, a0, 0, 0, 32);
		this.mult(b1, a1, a0, 32, 32, 0);
		this.add(c1, b1, b1, 0, 0, 32);
		this.sub(c1, b1, b1, 32, 0, 32);
		this.square(r, c1, 0, 32);
		this.sub(s, b0, b0, 0, 0, 32);
		this.mult121665(t, s, 0, 0);
		this.add(u, t, b0, 0, 0, 0);
		this.mult(xznb, b0, b0, 0, 0, 32);
		this.mult(xznb, s, u, 32, 0, 0);
		this.square(xzn1b, c1, 0, 0);
		this.mult(xzn1b, r, work, 32, 0, 0);
		this.select(xzm, xzm1, xznb, xzn1b, b);
	}
	for (var j = 0; j < 64; ++j) work[j] = xzm[j];
}
curve25519.recip = function(outv, z, ooff, zoff) { //outv[32], z[32]
	var z2 = ZeroArray(32);
	var z9 = ZeroArray(32);
	var z11 = ZeroArray(32);
	var z2_5_0 = ZeroArray(32);
	var z2_10_0 = ZeroArray(32);
	var z2_20_0 = ZeroArray(32);
	var z2_50_0 = ZeroArray(32);
	var z2_100_0 = ZeroArray(32);
	var t0 = ZeroArray(32);
	var t1 = ZeroArray(32);

	/* 2 */
	this.square(z2, z, 0, zoff);
	/* 4 */
	this.square(t1, z2, 0, 0);
	/* 8 */
	this.square(t0, t1, 0, 0);
	/* 9 */
	this.mult(z9, t0, z, 0, 0, zoff);
	/* 11 */
	this.mult(z11, z9, z2, 0, 0, 0);
	/* 22 */
	this.square(t0, z11, 0, 0);
	/* 2^5 - 2^0 = 31 */
	this.mult(z2_5_0, t0, z9, 0, 0, 0);
	/* 2^6 - 2^1 */
	this.square(t0, z2_5_0, 0, 0, 0);
	/* 2^7 - 2^2 */
	this.square(t1, t0, 0, 0);
	/* 2^8 - 2^3 */
	this.square(t0, t1, 0, 0);
	/* 2^9 - 2^4 */
	this.square(t1, t0, 0, 0);
	/* 2^10 - 2^5 */
	this.square(t0, t1, 0, 0);
	/* 2^10 - 2^0 */
	this.mult(z2_10_0, t0, z2_5_0, 0, 0, 0);

	/* 2^11 - 2^1 */
	this.square(t0, z2_10_0, 0, 0);
	/* 2^12 - 2^2 */
	this.square(t1, t0, 0, 0);
	/* 2^20 - 2^10 */
	for (var i = 2; i < 10; i += 2) { this.square(t0, t1, 0, 0); this.square(t1, t0, 0, 0); }
	/* 2^20 - 2^0 */
	this.mult(z2_20_0, t1, z2_10_0, 0, 0, 0);

	/* 2^21 - 2^1 */
	this.square(t0, z2_20_0, 0, 0);
	/* 2^22 - 2^2 */
	this.square(t1, t0, 0, 0);
	/* 2^40 - 2^20 */
	for (var i = 2; i < 20; i += 2) { this.square(t0, t1, 0, 0); this.square(t1, t0, 0, 0); }
	/* 2^40 - 2^0 */
	this.mult(t0, t1, z2_20_0, 0, 0, 0);

	/* 2^41 - 2^1 */
	this.square(t1, t0, 0, 0);
	/* 2^42 - 2^2 */
	this.square(t0, t1, 0, 0);
	/* 2^50 - 2^10 */
	for (var i = 2; i < 10; i += 2) { this.square(t1, t0, 0, 0); this.square(t0, t1, 0, 0); }
	/* 2^50 - 2^0 */
	this.mult(z2_50_0, t0, z2_10_0, 0, 0, 0);

	/* 2^51 - 2^1 */
	this.square(t0, z2_50_0, 0, 0);
	/* 2^52 - 2^2 */
	this.square(t1, t0, 0, 0);
	/* 2^100 - 2^50 */
	for (var i = 2; i < 50; i += 2) { this.square(t0, t1, 0, 0); this.square(t1, t0, 0, 0); }
	/* 2^100 - 2^0 */
	this.mult(z2_100_0, t1, z2_50_0, 0, 0, 0);

	/* 2^101 - 2^1 */
	this.square(t1, z2_100_0, 0, 0);
	/* 2^102 - 2^2 */
	this.square(t0, t1, 0, 0);
	/* 2^200 - 2^100 */
	for (var i = 2; i < 100; i += 2) { this.square(t1, t0, 0, 0); this.square(t0, t1, 0, 0); }
	/* 2^200 - 2^0 */
	this.mult(t1, t0, z2_100_0, 0, 0, 0);

	/* 2^201 - 2^1 */
	this.square(t0, t1, 0, 0);
	/* 2^202 - 2^2 */
	this.square(t1, t0, 0, 0);
	/* 2^250 - 2^50 */
	for (var i = 2; i < 50; i += 2) { this.square(t0, t1, 0, 0); this.square(t1, t0, 0, 0); }
	/* 2^250 - 2^0 */
	this.mult(t0, t1, z2_50_0, 0, 0, 0);

	/* 2^251 - 2^1 */
	this.square(t1, t0, 0, 0);
	/* 2^252 - 2^2 */
	this.square(t0, t1, 0, 0);
	/* 2^253 - 2^3 */
	this.square(t1, t0, 0, 0);
	/* 2^254 - 2^4 */
	this.square(t0, t1, 0, 0);
	/* 2^255 - 2^5 */
	this.square(t1, t0, 0, 0);
	/* 2^255 - 21 */
	this.mult(outv, t1, z11, ooff, 0, 0);
}
curve25519.crypto_scalarmult = function(q, n, p) {
	var work = ZeroArray(96);
	var e = new Array(32);
	for (var i = 0; i < 32; ++i) e[i] = n[i];
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;
	for (var i = 0; i < 32; ++i) work[i] = p[i];
	this.mainloop(work, e);
	this.recip(work, work, 32, 32);
	this.mult(work, work, work, 64, 0, 32);
	this.freeze(work, 64);
	for (var i = 0; i < 32; ++i) q[i] = work[64 + i]; //cast to (Byte)
	return 0;
}