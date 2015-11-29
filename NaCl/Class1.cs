using System;
using System.Diagnostics;
using UCIS.NaCl.Box;

namespace UCIS.NaCl {
	unsafe public class Class1 {
		public static void PrintHex(UInt32[] h) {
			Console.Write("Output: ");
			for (int i = 0; i < h.Length; i++) Console.Write(h[i].ToString("x2"));
			Console.WriteLine();
			Console.ReadLine();
		}
		public static void PrintHex(Byte[] h) {
			Console.Write("Output: ");
			for (int i = 0; i < h.Length; i++) Console.Write(h[i].ToString("x2"));
			Console.WriteLine();
		}
        
		public static void Main() {
			Byte[] skx = { 0xb5, 0xe8, 0xa, 0x23, 0xe5, 0xb1, 0x89, 0x4e, 0x1, 0x71, 0x6d, 0xc6, 0xd3, 0xaa, 0x87, 0xec, 0x8, 0x19, 0x1b, 0x17, 0x91, 0xcb, 0x9e, 0x7f, 0x81, 0x80, 0x4d, 0xb2, 0xd2, 0x2, 0x6f, 0x77 };
			Byte[] pkx = null;
			DateTime dt = DateTime.Now;
			for (int i = 0; i < 10; i++ ) {
				Curve25519XSalsa20Poly1305.GetPublicKey(out pkx, skx);
			}
			Console.WriteLine("Time: " + DateTime.Now.Subtract(dt).TotalMilliseconds.ToString());

			Console.Write("SECRET: ");
			for (int i = 0; i < Curve25519XSalsa20Poly1305.SECRETKEYBYTES; i++) Console.Write(skx[i].ToString("x2"));
			Console.WriteLine();

			Console.Write("PUBLIC: ");
			for (int i = 0; i < Curve25519XSalsa20Poly1305.SECRETKEYBYTES; i++) Console.Write(pkx[i].ToString("x2"));
			Console.WriteLine();
			//Console.ReadLine();
			//return;

			//curve25519xsalsa20poly1305 cb = new curve25519xsalsa20poly1305();
			Byte[] pk1, sk1, pk2, sk2;
			Curve25519XSalsa20Poly1305.KeyPair(out pk1, out sk1);
			Curve25519XSalsa20Poly1305.KeyPair(out pk2, out sk2);

			Console.WriteLine("Two key pairs:");

			Console.Write("SERCET 1: ");
			for (int i = 0; i < Curve25519XSalsa20Poly1305.SECRETKEYBYTES; i++) Console.Write(sk1[i].ToString("x2"));
			Console.WriteLine();

			Console.Write("PUBLIC 1: ");
			for (int i = 0; i < Curve25519XSalsa20Poly1305.PUBLICKEYBYTES; i++) Console.Write(pk1[i].ToString("x2"));
			Console.WriteLine();

			Console.Write("SERCET 2: ");
			for (int i = 0; i < Curve25519XSalsa20Poly1305.SECRETKEYBYTES; i++) Console.Write(sk2[i].ToString("x2"));
			Console.WriteLine();

			Console.Write("PUBLIC 2: ");
			for (int i = 0; i < Curve25519XSalsa20Poly1305.PUBLICKEYBYTES; i++) Console.Write(pk2[i].ToString("x2"));
			Console.WriteLine();

			Console.ReadLine();

			Byte[] n = new Byte[24];
			Byte[] c = new Byte[32 + 32];
			Byte[] m = new Byte[32 + 32];
			Byte[] r = new Byte[32 + 32];

			int mlen = 64;

			(new Random()).NextBytes(m);
			for (int i = 0; i < 32; i++) m[i] = 0;

			Console.Write("INPUT:  ");
			for (int i = 32; i < 64; i++) Console.Write(m[i].ToString("x2"));
			Console.WriteLine();

			int o1, o2;

            //Byte[] before1 = curve25519xsalsa20poly1305.crypto_box_beforenm(pk2, sk1);
            //Byte[] before2 = curve25519xsalsa20poly1305.crypto_box_beforenm(pk1, sk2);


            //o1 = curve25519xsalsa20poly1305.crypto_box_afternm(c, m, n, before1);
            //o2 = curve25519xsalsa20poly1305.crypto_box_open_afternm(r, c, n, before2);

            o1 = Curve25519XSalsa20Poly1305.Box(c, 0, m, 0, mlen, n, pk2, sk1);
            o2 = Curve25519XSalsa20Poly1305.Open(r, 0, c, 0, mlen, n, pk1, sk2);

			fixed (Byte* pk1p = pk1, sk1p = sk1, np = n, cp=c, mp=m, pk2p = pk2, sk2p = sk2, rp=r) {
				//o1 = curve25519xsalsa20poly1305.crypto_box(cp, mp, (ulong)mlen, np, pk2p, sk1p);
				//o2 = curve25519xsalsa20poly1305.crypto_box_open(rp, cp, (ulong)mlen, np, pk1p, sk2p);
			}

			Console.Write("OUTPUT: ");
			for (int i = 32; i < 64; i++) Console.Write(r[i].ToString("x2"));
			Console.WriteLine();

			Console.WriteLine("RESULT: {0} {1}", o1, o2);

			Console.ReadLine();
		}

        public static string BoxUnbox(string test)
        {
            return System.Text.ASCIIEncoding.ASCII.GetString(BoxUnbox(System.Text.ASCIIEncoding.ASCII.GetBytes(test)));
        }

        public static byte[] BoxUnbox(byte[] test)
        {
            byte[] alicePK, aliceSK, bobPK, bobSK;
            Curve25519XSalsa20Poly1305.KeyPair(out alicePK, out aliceSK);
            Curve25519XSalsa20Poly1305.KeyPair(out bobPK, out bobSK);
            byte[] nonce = NewNonce();
            byte[] cipher = new byte[test.Length + 32];
            byte[] message = new byte[test.Length + 32];
            byte[] messageDecrypted = new byte[test.Length + 32];
            Buffer.BlockCopy(test, 0, message, 32, test.Length);

            Curve25519XSalsa20Poly1305.Box(cipher, message, nonce, bobPK, aliceSK);
            Curve25519XSalsa20Poly1305.Open(messageDecrypted, cipher, nonce, alicePK, bobSK);

            byte[] clear = new byte[messageDecrypted.Length - 32]; 
            Buffer.BlockCopy( messageDecrypted, 32, clear, 0, messageDecrypted.Length - 32);
            return clear;
        }

       

        public static double EncryptRateTest(int messageSize)
        {
            int count = 1000;
            byte[] alicePK, aliceSK, bobPK, bobSK;
            Curve25519XSalsa20Poly1305.KeyPair(out alicePK, out aliceSK);
            Curve25519XSalsa20Poly1305.KeyPair(out bobPK, out bobSK);
            byte[] message = new byte[messageSize + 32];
            byte[] cipher = new byte[messageSize + 32];

            RandomBytes.generate(message);
            Stopwatch sw = new Stopwatch();
            sw.Start();
            for (int i = 0; i < count; i++)
            {
                Curve25519XSalsa20Poly1305.Box(cipher, message, NewNonce(), bobPK, aliceSK);
            }
            sw.Stop();
            return count / sw.Elapsed.TotalSeconds;
        }

        public static byte[] NewNonce()
        {
            byte[] guid = Guid.NewGuid().ToByteArray();
            byte[] prefix = new byte[8] { 0, 1, 2, 3, 4, 5, 6, 7 };
            byte[] nonce = new byte[24];
            Buffer.BlockCopy(prefix, 0, nonce, 0, 8);
            Buffer.BlockCopy(guid, 0, nonce, 8, 16);
            return nonce;
        }
	}
}
