package ax.xz.wireguard.noise.crypto.internal;

abstract class Scalar25519
{
	static final int SIZE = 8;

	private static final int[] L = new int[]{ 0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000,
			0x00000000, 0x10000000 };

	static void decode(byte[] k, int[] n)
	{
		Codec.decode32(k, 0, n, 0, SIZE);
	}

	static void toSignedDigits(int bits, int[] z)
	{
//        assert bits == 256;
//        assert z.length >= SIZE;

//        int c1 =
		Nat.caddTo(SIZE, ~z[0] & 1, L, z);     //assert c1 == 0;
//        int c2 =
		Nat.shiftDownBit(SIZE, z, 1);           //assert c2 == (1 << 31);
	}
}