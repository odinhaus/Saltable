using System;

namespace Altus.Saltable {
	class RandomBytes {
		static Random rnd = new Random();
		public static void generate(Byte[] x) {
			rnd.NextBytes(x);
		}
	}
}