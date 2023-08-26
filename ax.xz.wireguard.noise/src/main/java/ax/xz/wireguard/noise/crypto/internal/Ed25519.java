package ax.xz.wireguard.noise.crypto.internal;


import ax.xz.wireguard.noise.crypto.X25519;

/**
 * A low-level implementation of the Ed25519, Ed25519ctx, and Ed25519ph instantiations of the Edwards-Curve
 * Digital Signature Algorithm specified in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>.
 * <p>
 * The implementation strategy is mostly drawn from <a href="https://ia.cr/2012/309"> Mike Hamburg, "Fast and
 * compact elliptic-curve cryptography"</a>, notably the "signed multi-comb" algorithm (for scalar
 * multiplication by a fixed point), the "half Niels coordinates" (for precomputed points), and the
 * "extensible coordinates" (for accumulators). Standard
 * <a href="https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html">extended coordinates</a> are used
 * during precomputations, needing only a single extra point addition formula.
 */
public abstract class Ed25519
{
	// -x^2 + y^2 == 1 + 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3 * x^2 * y^2
	public static final class PublicPoint
	{
		final int[] data;

		PublicPoint(int[] data)
		{
			this.data = data;
		}
	}

	private static class F extends X25519Field {};

	private static final int SCALAR_INTS = 8;
	private static final int SCALAR_BYTES = SCALAR_INTS * 4;

	private static final int[] B_x = new int[]{ 0x0325D51A, 0x018B5823, 0x007B2C95, 0x0304A92D, 0x00D2598E, 0x01D6DC5C,
			0x01388C7F, 0x013FEC0A, 0x029E6B72, 0x0042D26D };
	private static final int[] B_y = new int[]{ 0x02666658, 0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, 0x02666666,
			0x01999999, 0x00666666, 0x03333333, 0x00CCCCCC, };

	// 2^128 * B
	private static final int[] B128_x = new int[]{ 0x00B7E824, 0x0011EB98, 0x003E5FC8, 0x024E1739, 0x0131CD0B,
			0x014E29A0, 0x034E6138, 0x0132C952, 0x03F9E22F, 0x00984F5F };
	private static final int[] B128_y = new int[]{ 0x03F5A66B, 0x02AF4452, 0x0049E5BB, 0x00F28D26, 0x0121A17C,
			0x02C29C3A, 0x0047AD89, 0x0087D95F, 0x0332936E, 0x00BE5933 };

	// Note that d == -121665/121666
	private static final int[] C_d = new int[]{ 0x035978A3, 0x02D37284, 0x018AB75E, 0x026A0A0E, 0x0000E014, 0x0379E898,
			0x01D01E5D, 0x01E738CC, 0x03715B7F, 0x00A406D9 };
	private static final int[] C_d2 = new int[]{ 0x02B2F159, 0x01A6E509, 0x01156EBD, 0x00D4141D, 0x0001C029, 0x02F3D130,
			0x03A03CBB, 0x01CE7198, 0x02E2B6FF, 0x00480DB3 };
	private static final int[] C_d4 = new int[]{ 0x0165E2B2, 0x034DCA13, 0x002ADD7A, 0x01A8283B, 0x00038052, 0x01E7A260,
			0x03407977, 0x019CE331, 0x01C56DFF, 0x00901B67 };

	private static final int WNAF_WIDTH_BASE = 6;

	// scalarMultBase is hard-coded for these values of blocks, teeth, spacing so they can't be freely changed
	private static final int PRECOMP_BLOCKS = 8;
	private static final int PRECOMP_TEETH = 4;
	private static final int PRECOMP_SPACING = 8;
	private static final int PRECOMP_RANGE = PRECOMP_BLOCKS * PRECOMP_TEETH * PRECOMP_SPACING; // range == 256
	private static final int PRECOMP_POINTS = 1 << (PRECOMP_TEETH - 1);
	private static final int PRECOMP_MASK = PRECOMP_POINTS - 1;

	private static final Object PRECOMP_LOCK = new Object();
	private static int[] PRECOMP_BASE_COMB = null;

	private static class PointAccum
	{
		int[] x = F.create();
		int[] y = F.create();
		int[] z = F.create();
		int[] u = F.create();
		int[] v = F.create();
	}

	private static class PointAffine
	{
		int[] x = F.create();
		int[] y = F.create();
	}

	private static class PointExtended
	{
		int[] x = F.create();
		int[] y = F.create();
		int[] z = F.create();
		int[] t = F.create();
	}

	private static class PointPrecomp
	{
		int[] ymx_h = F.create();       // (y - x)/2
		int[] ypx_h = F.create();       // (y + x)/2
		int[] xyd = F.create();         // x.y.d
	}

	// Temp space to avoid allocations in point formulae.
	private static class PointTemp
	{
		int[] r0 = F.create();
		int[] r1 = F.create();;
	}

	private static int checkPoint(PointAccum p)
	{
		int[] t = F.create();
		int[] u = F.create();
		int[] v = F.create();
		int[] w = F.create();

		F.sqr(p.x, u);
		F.sqr(p.y, v);
		F.sqr(p.z, w);
		F.mul(u, v, t);
		F.sub(v, u, v);
		F.mul(v, w, v);
		F.sqr(w, w);
		F.mul(t, C_d, t);
		F.add(t, w, t);
		F.sub(t, v, t);
		F.normalize(t);

		return F.isZero(t);
	}


	private static void groupCombBits(int[] n)
	{
		/*
		 * Because we are using 4 teeth and 8 spacing, each limb of n corresponds to one of the 8 blocks.
		 * Therefore we can efficiently group the bits for each comb position using a (double) shuffle.
		 */
		for (int i = 0; i < n.length; ++i)
		{
			n[i] = shuffle2(n[i]);
		}
	}

	public static int shuffle2(int x)
	{
		// "shuffle" (twice) low half to even bits and high half to odd bits
		x = bitPermuteStep(x, 0x00AA00AA, 7);
		x = bitPermuteStep(x, 0x0000CCCC, 14);
		x = bitPermuteStep(x, 0x00F000F0, 4);
		x = bitPermuteStep(x, 0x0000FF00, 8);
		return x;
	}

	public static int bitPermuteStep(int x, int m, int s)
	{
		int t = (x ^ (x >>> s)) & m;
		return  (t ^ (t <<  s)) ^ x;
	}


	private static void invertDoubleZs(PointExtended[] points)
	{
		int count = points.length;
		int[] cs = F.createTable(count);

		int[] u = F.create();
		F.copy(points[0].z, 0, u, 0);
		F.copy(u, 0, cs, 0);

		int i = 0;
		while (++i < count)
		{
			F.mul(u, points[i].z, u);
			F.copy(u, 0, cs, i * F.SIZE);
		}

		F.add(u, u, u);
		F.invVar(u, u);
		--i;

		int[] t = F.create();

		while (i > 0)
		{
			int j = i--;
			F.copy(cs, i * F.SIZE, t, 0);
			F.mul(t, u, t);
			F.mul(u, points[j].z, u);
			F.copy(t, 0, points[j].z, 0);
		}

		F.copy(u, 0, points[0].z, 0);
	}

	private static void pointAdd(PointExtended p, PointExtended q, PointExtended r, PointTemp t)
	{
		// p may ref the same point as r (or q), but q may not ref the same point as r.
//        assert q != r;

		int[] a = r.x;
		int[] b = r.y;
		int[] c = t.r0;
		int[] d = t.r1;
		int[] e = a;
		int[] f = c;
		int[] g = d;
		int[] h = b;

		F.apm(p.y, p.x, b, a);
		F.apm(q.y, q.x, d, c);
		F.mul(a, c, a);
		F.mul(b, d, b);
		F.mul(p.t, q.t, c);
		F.mul(c, C_d2, c);
		F.add(p.z, p.z, d);
		F.mul(d, q.z, d);
		F.apm(b, a, h, e);
		F.apm(d, c, g, f);
		F.mul(e, h, r.t);
		F.mul(f, g, r.z);
		F.mul(e, f, r.x);
		F.mul(h, g, r.y);
	}

	private static void pointAdd(PointPrecomp p, PointAccum r, PointTemp t)
	{
		int[] a = r.x;
		int[] b = r.y;
		int[] c = t.r0;
		int[] e = r.u;
		int[] f = a;
		int[] g = b;
		int[] h = r.v;

		F.apm(r.y, r.x, b, a);
		F.mul(a, p.ymx_h, a);
		F.mul(b, p.ypx_h, b);
		F.mul(r.u, r.v, c);
		F.mul(c, p.xyd, c);
		F.apm(b, a, h, e);
		F.apm(r.z, c, g, f);
		F.mul(f, g, r.z);
		F.mul(f, e, r.x);
		F.mul(g, h, r.y);
	}

	private static void pointCopy(PointAccum p, PointExtended r)
	{
		F.copy(p.x, 0, r.x, 0);
		F.copy(p.y, 0, r.y, 0);
		F.copy(p.z, 0, r.z, 0);
		F.mul(p.u, p.v, r.t);
	}

	private static void pointCopy(PointAffine p, PointExtended r)
	{
		F.copy(p.x, 0, r.x, 0);
		F.copy(p.y, 0, r.y, 0);
		F.one(r.z);
		F.mul(p.x, p.y, r.t);
	}

	private static void pointDouble(PointAccum r)
	{
		int[] a = r.x;
		int[] b = r.y;
		int[] c = r.z;
		int[] e = r.u;
		int[] f = a;
		int[] g = b;
		int[] h = r.v;

		F.add(r.x, r.y, e);
		F.sqr(r.x, a);
		F.sqr(r.y, b);
		F.sqr(r.z, c);
		F.add(c, c, c);
		F.apm(a, b, h, g);
		F.sqr(e, e);
		F.sub(h, e, e);
		F.add(c, g, f);
		F.carry(f); // Probably unnecessary, but keep until better bounds analysis available
		F.mul(f, g, r.z);
		F.mul(f, e, r.x);
		F.mul(g, h, r.y);
	}

	private static void pointLookup(int block, int index, PointPrecomp p)
	{
//        assert 0 <= block && block < PRECOMP_BLOCKS;
//        assert 0 <= index && index < PRECOMP_POINTS;

		int off = block * PRECOMP_POINTS * 3 * F.SIZE;

		for (int i = 0; i < PRECOMP_POINTS; ++i)
		{
			int cond = ((i ^ index) - 1) >> 31;
			F.cmov(cond, PRECOMP_BASE_COMB, off, p.ymx_h, 0);     off += F.SIZE;
			F.cmov(cond, PRECOMP_BASE_COMB, off, p.ypx_h, 0);     off += F.SIZE;
			F.cmov(cond, PRECOMP_BASE_COMB, off, p.xyd,   0);     off += F.SIZE;
		}
	}

	private static void pointPrecompute(PointAffine p, PointExtended[] points, int pointsOff, int pointsLen,
										PointTemp t)
	{
//        assert pointsLen > 0;

		pointCopy(p, points[pointsOff] = new PointExtended());

		PointExtended d = new PointExtended();
		pointAdd(points[pointsOff], points[pointsOff], d, t);

		for (int i = 1; i < pointsLen; ++i)
		{
			pointAdd(points[pointsOff + i - 1], d, points[pointsOff + i] = new PointExtended(), t);
		}
	}

	private static void pointSetNeutral(PointAccum p)
	{
		F.zero(p.x);
		F.one(p.y);
		F.one(p.z);
		F.zero(p.u);
		F.one(p.v);
	}

	public static void precompute()
	{
		synchronized (PRECOMP_LOCK)
		{
			if (PRECOMP_BASE_COMB != null)
			{
				return;
			}

			int wnafPoints = 1 << (WNAF_WIDTH_BASE - 2);
			int combPoints = PRECOMP_BLOCKS * PRECOMP_POINTS;
			int totalPoints = wnafPoints * 2 + combPoints;

			PointExtended[] points = new PointExtended[totalPoints];
			PointTemp t = new PointTemp();

			PointAffine B = new PointAffine();
			F.copy(B_x, 0, B.x, 0);
			F.copy(B_y, 0, B.y, 0);

			pointPrecompute(B, points, 0, wnafPoints, t);

			PointAffine B128 = new PointAffine();
			F.copy(B128_x, 0, B128.x, 0);
			F.copy(B128_y, 0, B128.y, 0);

			pointPrecompute(B128, points, wnafPoints, wnafPoints, t);

			PointAccum p = new PointAccum();
			F.copy(B_x, 0, p.x, 0);
			F.copy(B_y, 0, p.y, 0);
			F.one(p.z);
			F.copy(p.x, 0, p.u, 0);
			F.copy(p.y, 0, p.v, 0);

			int pointsIndex = wnafPoints * 2;
			PointExtended[] toothPowers = new PointExtended[PRECOMP_TEETH];
			for (int tooth = 0; tooth < PRECOMP_TEETH; ++tooth)
			{
				toothPowers[tooth] = new PointExtended();
			}

			PointExtended u = new PointExtended();
			for (int block = 0; block < PRECOMP_BLOCKS; ++block)
			{
				PointExtended sum = points[pointsIndex++] = new PointExtended();

				for (int tooth = 0; tooth < PRECOMP_TEETH; ++tooth)
				{
					if (tooth == 0)
					{
						pointCopy(p, sum);
					}
					else
					{
						pointCopy(p, u);
						pointAdd(sum, u, sum, t);
					}

					pointDouble(p);
					pointCopy(p, toothPowers[tooth]);

					if (block + tooth != PRECOMP_BLOCKS + PRECOMP_TEETH - 2)
					{
						for (int spacing = 1; spacing < PRECOMP_SPACING; ++spacing)
						{
							pointDouble(p);
						}
					}
				}

				F.negate(sum.x, sum.x);
				F.negate(sum.t, sum.t);

				for (int tooth = 0; tooth < (PRECOMP_TEETH - 1); ++tooth)
				{
					int size = 1 << tooth;
					for (int j = 0; j < size; ++j, ++pointsIndex)
					{
						points[pointsIndex] = new PointExtended();
						pointAdd(points[pointsIndex - size], toothPowers[tooth], points[pointsIndex], t);
					}
				}
			}
//            assert pointsIndex == totalPoints;

			// Set each z coordinate to 1/(2.z) to avoid calculating halves of x, y in the following code
			invertDoubleZs(points);

			PointPrecomp[] PRECOMP_BASE_WNAF = new PointPrecomp[wnafPoints];
			for (int i = 0; i < wnafPoints; ++i)
			{
				PointExtended q = points[i];
				PointPrecomp r = PRECOMP_BASE_WNAF[i] = new PointPrecomp();

				// Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
				F.mul(q.x, q.z, q.x);
				F.mul(q.y, q.z, q.y);

				// y/2 +/- x/2
				F.apm(q.y, q.x, r.ypx_h, r.ymx_h);

				// x/2 * y/2 * (4.d) == x.y.d
				F.mul(q.x, q.y, r.xyd);
				F.mul(r.xyd, C_d4, r.xyd);

				F.normalize(r.ymx_h);
				F.normalize(r.ypx_h);
				F.normalize(r.xyd);
			}

			PointPrecomp[] PRECOMP_BASE128_WNAF = new PointPrecomp[wnafPoints];
			for (int i = 0; i < wnafPoints; ++i)
			{
				PointExtended q = points[wnafPoints + i];
				PointPrecomp r = PRECOMP_BASE128_WNAF[i] = new PointPrecomp();

				// Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
				F.mul(q.x, q.z, q.x);
				F.mul(q.y, q.z, q.y);

				// y/2 +/- x/2
				F.apm(q.y, q.x, r.ypx_h, r.ymx_h);

				// x/2 * y/2 * (4.d) == x.y.d
				F.mul(q.x, q.y, r.xyd);
				F.mul(r.xyd, C_d4, r.xyd);

				F.normalize(r.ymx_h);
				F.normalize(r.ypx_h);
				F.normalize(r.xyd);
			}

			PRECOMP_BASE_COMB = F.createTable(combPoints * 3);
			PointPrecomp s = new PointPrecomp();
			int off = 0;
			for (int i = wnafPoints * 2; i < totalPoints; ++i)
			{
				PointExtended q = points[i];

				// Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
				F.mul(q.x, q.z, q.x);
				F.mul(q.y, q.z, q.y);

				// y/2 +/- x/2
				F.apm(q.y, q.x, s.ypx_h, s.ymx_h);

				// x/2 * y/2 * (4.d) == x.y.d
				F.mul(q.x, q.y, s.xyd);
				F.mul(s.xyd, C_d4, s.xyd);

				F.normalize(s.ymx_h);
				F.normalize(s.ypx_h);
				F.normalize(s.xyd);

				F.copy(s.ymx_h, 0, PRECOMP_BASE_COMB, off);       off += F.SIZE;
				F.copy(s.ypx_h, 0, PRECOMP_BASE_COMB, off);       off += F.SIZE;
				F.copy(s.xyd  , 0, PRECOMP_BASE_COMB, off);       off += F.SIZE;
			}
//            assert off == PRECOMP_BASE_COMB.length;
		}
	}

	private static void pruneScalar(byte[] n, int nOff, byte[] r)
	{
		System.arraycopy(n, nOff, r, 0, SCALAR_BYTES);

		r[0] &= 0xF8;
		r[SCALAR_BYTES - 1] &= 0x7F;
		r[SCALAR_BYTES - 1] |= 0x40;
	}

	private static void scalarMultBase(byte[] k, PointAccum r)
	{
		// Equivalent (but much slower)
//        PointAffine p = new PointAffine();
//        F.copy(B_x, 0, p.x, 0);
//        F.copy(B_y, 0, p.y, 0);
//        scalarMult(k, p, r);

		precompute();

		int[] n = new int[SCALAR_INTS];
		Scalar25519.decode(k, n);
		Scalar25519.toSignedDigits(PRECOMP_RANGE, n);
		groupCombBits(n);

		PointPrecomp p = new PointPrecomp();
		PointTemp t = new PointTemp();

		pointSetNeutral(r);
		int resultSign = 0;

		int cOff = (PRECOMP_SPACING - 1) * PRECOMP_TEETH;
		for (;;)
		{
			for (int block = 0; block < PRECOMP_BLOCKS; ++block)
			{
				int w = n[block] >>> cOff;
				int sign = (w >>> (PRECOMP_TEETH - 1)) & 1;
				int abs = (w ^ -sign) & PRECOMP_MASK;

//                assert sign == 0 || sign == 1;
//                assert 0 <= abs && abs < PRECOMP_POINTS;

				pointLookup(block, abs, p);

				F.cnegate(resultSign ^ sign, r.x);
				F.cnegate(resultSign ^ sign, r.u);
				resultSign = sign;

				pointAdd(p, r, t);
			}

			if ((cOff -= PRECOMP_TEETH) < 0)
			{
				break;
			}

			pointDouble(r);
		}

		F.cnegate(resultSign, r.x);
		F.cnegate(resultSign, r.u);
	}

	/**
	 * NOTE: Only for use by X25519
	 */
	public static void scalarMultBaseYZ(X25519.Friend friend, byte[] k, int kOff, int[] y, int[] z)
	{
		if (null == friend)
		{
			throw new NullPointerException("This method is only for use by X25519");
		}

		byte[] n = new byte[SCALAR_BYTES];
		pruneScalar(k, kOff, n);

		PointAccum p = new PointAccum();
		scalarMultBase(n, p);
		if (0 == checkPoint(p))
		{
			throw new IllegalStateException();
		}

		F.copy(p.y, 0, y, 0);
		F.copy(p.z, 0, z, 0);
	}

}