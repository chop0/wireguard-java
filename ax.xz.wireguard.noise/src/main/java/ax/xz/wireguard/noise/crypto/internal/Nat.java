package ax.xz.wireguard.noise.crypto.internal;

public abstract class Nat
{
	private static final long M = 0xFFFFFFFFL;

	public static int caddTo(int len, int mask, int[] x, int[] z)
	{
		long MASK = -(mask & 1) & M;
		long c = 0;
		for (int i = 0; i < len; ++i)
		{
			c += (z[i] & M) + (x[i] & MASK);
			z[i] = (int)c;
			c >>>= 32;
		}
		return (int)c;
	}

	public static int equalTo(int len, int[] x, int y)
	{
		int d = x[0] ^ y;
		for (int i = 1; i < len; ++i)
		{
			d |= x[i];
		}
		d = (d >>> 1) | (d & 1);
		return (d - 1) >> 31;
	}

	public static int equalToZero(int len, int[] x)
	{
		int d = 0;
		for (int i = 0; i < len; ++i)
		{
			d |= x[i];
		}
		d = (d >>> 1) | (d & 1);
		return (d - 1) >> 31;
	}

	public static boolean isOne(int len, int[] x)
	{
		if (x[0] != 1)
		{
			return false;
		}
		for (int i = 1; i < len; ++i)
		{
			if (x[i] != 0)
			{
				return false;
			}
		}
		return true;
	}

	public static boolean isZero(int len, int[] x)
	{
		for (int i = 0; i < len; ++i)
		{
			if (x[i] != 0)
			{
				return false;
			}
		}
		return true;
	}

	public static int shiftDownBit(int len, int[] z, int c)
	{
		int i = len;
		while (--i >= 0)
		{
			int next = z[i];
			z[i] = (next >>> 1) | (c << 31);
			c = next;
		}
		return c << 31;
	}


}