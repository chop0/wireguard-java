package ax.xz.wireguard.noise.crypto;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorShuffle;
import jdk.incubator.vector.VectorSpecies;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteOrder;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static jdk.incubator.vector.VectorOperators.ROL;
import static jdk.incubator.vector.VectorOperators.XOR;

public class ChaCha20 {
	private static final int BLOCK_SIZE = 64;

	// Method to initialize the state matrix
	static void initializeState(byte[] key, byte[] nonce, int[] state, int counter) {
		if (state.length != 16) {
			throw new IllegalArgumentException("State size must be 16 words");
		}

		// Constants
		state[0] = 0x61707865;
		state[1] = 0x3320646e;
		state[2] = 0x79622d32;
		state[3] = 0x6b206574;

		// Key
		for (int i = 0; i < 8; i++) {
			state[4 + i] = byteArrayToIntLittleEndian(key, i * 4);
		}

		// Block counter
		state[12] = counter;

		// Nonce
		state[13] = byteArrayToIntLittleEndian(nonce, 0);
		state[14] = byteArrayToIntLittleEndian(nonce, 4);
		state[15] = byteArrayToIntLittleEndian(nonce, 8);
	}

	static int byteArrayToIntLittleEndian(byte[] b, int offset) {
		return (b[offset] & 0xFF) |
			   ((b[offset + 1] & 0xFF) << 8) |
			   ((b[offset + 2] & 0xFF) << 16) |
			   ((b[offset + 3] & 0xFF) << 24);
	}


	static int rotateLeft(int N, int S) {
		return ((N >>> (~S)) >>> 1) | (N << S);
	}

	// Method to perform the quarter round operation
	static void quarterRound(int[] state, int a, int b, int c, int d) {
		state[a] += state[b];
		state[d] ^= state[a];
		state[d] = rotateLeft(state[d], 16);
		state[c] += state[d];
		state[b] ^= state[c];
		state[b] = rotateLeft(state[b], 12);
		state[a] += state[b];
		state[d] ^= state[a];
		state[d] = rotateLeft(state[d], 8);
		state[c] += state[d];
		state[b] ^= state[c];
		state[b] = rotateLeft(state[b], 7);
	}

	private static <T> VectorShuffle<T> rotateLanes(VectorSpecies<T> species, int amount) {
		if (amount < 0)
			amount += species.length();
		return VectorShuffle.fromValues(species, (amount + 0) % species.length(), (amount + 1) % species.length(), (amount + 2) % species.length(), (amount + 3) % species.length());
	}

	private static final VectorShuffle<Integer> ROTATE_1 = rotateLanes(IntVector.SPECIES_128, 1);
	private static final VectorShuffle<Integer> ROTATE_2 = rotateLanes(IntVector.SPECIES_128, 2);
	private static final VectorShuffle<Integer> ROTATE_3 = rotateLanes(IntVector.SPECIES_128, 3);


	// Method to perform the ChaCha20 block function
	static void chacha20Block(int[] initialState, MemorySegment output, int counter) {
		var a = IntVector.fromArray(IntVector.SPECIES_128, initialState, 0);
		var b = IntVector.fromArray(IntVector.SPECIES_128, initialState, 4);
		var c = IntVector.fromArray(IntVector.SPECIES_128, initialState, 8);
		var d = IntVector.fromArray(IntVector.SPECIES_128, initialState, 12);

		d = d.withLane(0, counter);

		var aOrig = a;
		var bOrig = b;
		var cOrig = c;
		var dOrig = d;

		for (int i = 0; i < 10; i++) {
			a = a.add(b);
			d = d.lanewise(XOR, a);
			d = d.lanewise(ROL, 16);
			c = c.add(d);
			b = b.lanewise(XOR, c);
			b = b.lanewise(ROL, 12);
			a = a.add(b);
			d = d.lanewise(XOR, a);
			d = d.lanewise(ROL, 8);
			c = c.add(d);
			b = b.lanewise(XOR, c);
			b = b.lanewise(ROL, 7);

			a = a;
			b = b.rearrange(ROTATE_1);
			c = c.rearrange(ROTATE_2);
			d = d.rearrange(ROTATE_3);

			a = a.add(b);
			d = d.lanewise(XOR, a);
			d = d.lanewise(ROL, 16);
			c = c.add(d);
			b = b.lanewise(XOR, c);
			b = b.lanewise(ROL, 12);
			a = a.add(b);
			d = d.lanewise(XOR, a);
			d = d.lanewise(ROL, 8);
			c = c.add(d);
			b = b.lanewise(XOR, c);
			b = b.lanewise(ROL, 7);

			a = a;
			b = b.rearrange(ROTATE_3);
			c = c.rearrange(ROTATE_2);
			d = d.rearrange(ROTATE_1);
		}

		a = a.add(aOrig);
		b = b.add(bOrig);
		c = c.add(cOrig);
		d = d.add(dOrig);

		a.intoMemorySegment(output, 0, ByteOrder.nativeOrder());
		b.intoMemorySegment(output, 16, ByteOrder.nativeOrder());
		c.intoMemorySegment(output, 32, ByteOrder.nativeOrder());
		d.intoMemorySegment(output, 48, ByteOrder.nativeOrder());
	}

	static void doubleRound(MemorySegment state) {
		var a = IntVector.fromMemorySegment(IntVector.SPECIES_128, state, 0, ByteOrder.nativeOrder());
		var b = IntVector.fromMemorySegment(IntVector.SPECIES_128, state, 16, ByteOrder.nativeOrder());
		var c = IntVector.fromMemorySegment(IntVector.SPECIES_128, state, 32, ByteOrder.nativeOrder());
		var d = IntVector.fromMemorySegment(IntVector.SPECIES_128, state, 48, ByteOrder.nativeOrder());

		a = a.add(b);
		d = d.lanewise(XOR, a);
		d = d.lanewise(ROL, 16);
		c = c.add(d);
		b = b.lanewise(XOR, c);
		b = b.lanewise(ROL, 12);
		a = a.add(b);
		d = d.lanewise(XOR, a);
		d = d.lanewise(ROL, 8);
		c = c.add(d);
		b = b.lanewise(XOR, c);
		b = b.lanewise(ROL, 7);

		a = a;
		b = b.rearrange(ROTATE_1);
		c = c.rearrange(ROTATE_2);
		d = d.rearrange(ROTATE_3);

		a = a.add(b);
		d = d.lanewise(XOR, a);
		d = d.lanewise(ROL, 16);
		c = c.add(d);
		b = b.lanewise(XOR, c);
		b = b.lanewise(ROL, 12);
		a = a.add(b);
		d = d.lanewise(XOR, a);
		d = d.lanewise(ROL, 8);
		c = c.add(d);
		b = b.lanewise(XOR, c);
		b = b.lanewise(ROL, 7);

		a = a;
		b = b.rearrange(ROTATE_3);
		c = c.rearrange(ROTATE_2);
		d = d.rearrange(ROTATE_1);

		a.intoMemorySegment(state, 0, ByteOrder.nativeOrder());
		b.intoMemorySegment(state, 16, ByteOrder.nativeOrder());
		c.intoMemorySegment(state, 32, ByteOrder.nativeOrder());
		d.intoMemorySegment(state, 48, ByteOrder.nativeOrder());
	}

	// Method to encrypt or decrypt data
	static void chacha20(byte[] key, byte[] nonce, MemorySegment src, MemorySegment dst, int counter) {
		int[] initialState = new int[16];
		initializeState(key, nonce, initialState, 0);

		long inputRemaining = src.byteSize();
		int streamPosition = 0;

		while (inputRemaining > 0) {
			var a = IntVector.fromArray(IntVector.SPECIES_128, initialState, 0);
			var b = IntVector.fromArray(IntVector.SPECIES_128, initialState, 4);
			var c = IntVector.fromArray(IntVector.SPECIES_128, initialState, 8);
			var d = IntVector.fromArray(IntVector.SPECIES_128, initialState, 12);

			d = d.withLane(0, counter++);

			var aOrig = a;
			var bOrig = b;
			var cOrig = c;
			var dOrig = d;

			for (int i1 = 0; i1 < 10; i1++) {
				a = a.add(b);
				d = d.lanewise(XOR, a);
				d = d.lanewise(ROL, 16);
				c = c.add(d);
				b = b.lanewise(XOR, c);
				b = b.lanewise(ROL, 12);
				a = a.add(b);
				d = d.lanewise(XOR, a);
				d = d.lanewise(ROL, 8);
				c = c.add(d);
				b = b.lanewise(XOR, c);
				b = b.lanewise(ROL, 7);

				a = a;
				b = b.rearrange(ROTATE_1);
				c = c.rearrange(ROTATE_2);
				d = d.rearrange(ROTATE_3);

				a = a.add(b);
				d = d.lanewise(XOR, a);
				d = d.lanewise(ROL, 16);
				c = c.add(d);
				b = b.lanewise(XOR, c);
				b = b.lanewise(ROL, 12);
				a = a.add(b);
				d = d.lanewise(XOR, a);
				d = d.lanewise(ROL, 8);
				c = c.add(d);
				b = b.lanewise(XOR, c);
				b = b.lanewise(ROL, 7);

				a = a;
				b = b.rearrange(ROTATE_3);
				c = c.rearrange(ROTATE_2);
				d = d.rearrange(ROTATE_1);
			}

			a = a.add(aOrig);
			b = b.add(bOrig);
			c = c.add(cOrig);
			d = d.add(dOrig);

			int toProcess = Math.min((int) inputRemaining, BLOCK_SIZE);
			int inputRemainingThisBlock = toProcess;

			int blockPosition = 0;

			for (var keyStreamVector : new IntVector[]{a, b, c, d}) {
				// if we have fewer than 16 bytes left, we need to process them individually and then break
				if (inputRemainingThisBlock < 16) {
					for (int i = 0; i < inputRemainingThisBlock; i++) {
						dst.set(JAVA_BYTE, streamPosition + blockPosition + i, (byte) (keyStreamVector.reinterpretAsBytes().lane(i) ^ src.get(JAVA_BYTE, streamPosition + blockPosition + i)));
					}

					break;
				}

				var srcVector = IntVector.fromMemorySegment(IntVector.SPECIES_128, src, streamPosition + blockPosition, ByteOrder.nativeOrder());
				srcVector.lanewise(XOR, keyStreamVector).intoMemorySegment(dst, streamPosition + blockPosition, ByteOrder.nativeOrder());

				inputRemainingThisBlock -= 16;
				blockPosition += 16;
			}

			inputRemaining -= toProcess;
			streamPosition += toProcess;
		}
	}

	// Main method for testing
	public static void main(String[] args) {
		// TODO: add some test vectors to validate the implementation
	}
}
