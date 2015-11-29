using System;

namespace UCIS.NaCl {
	class RandomBytes {
		static Random rnd = new Random();
		public static void generate(Byte[] x) {
			rnd.NextBytes(x);
		}
	}
}