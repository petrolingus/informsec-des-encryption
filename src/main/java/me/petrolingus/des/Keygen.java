package me.petrolingus.des;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.BitSet;
import java.util.List;

public class Keygen {

    private static final int[] C_ZERO = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51,
            43, 35, 27, 19, 11, 3, 60, 52, 44, 36};

    private static final int[] D_ZERO = {63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53,
            45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

    private static final int[] S = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    private static final int[] IP = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16,
            7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42,
            50, 36, 29, 32};

    private final List<BitSet> keys;

    public Keygen(String base64Key) {

        keys = new ArrayList<>();

        BitSet key = BitSet.valueOf(Base64.getDecoder().decode(base64Key.getBytes(StandardCharsets.UTF_8)));

        BitSet c = initialPermutation(key, C_ZERO);
        BitSet d = initialPermutation(key, D_ZERO);

        for (int i = 0; i < 16; i++) {
            c = leftShiftBitSet(c, S[i]);
            d = leftShiftBitSet(d, S[i]);
            keys.add(createKey(combineBitSets(c, d)));
        }
    }

    public BitSet getKey(int i) {
        return keys.get(i);
    }

    private BitSet initialPermutation(BitSet key, int[] permutations) {
        BitSet result = new BitSet(28);
        for (int i = 0; i < 28; i++) {
            result.set(i, key.get(permutations[i] - 1));
        }
        return result;
    }

    private static BitSet leftShiftBitSet(BitSet bitSet, int shift) {
        BitSet result = new BitSet(28);
        for (int i = 0; i < 28; i++) {
            int id = (i - shift < 0) ? 28 + i - shift : i - shift;
            result.set(i, bitSet.get(id));
        }
        return result;
    }

    private BitSet combineBitSets(BitSet c, BitSet d) {
        BitSet result = new BitSet(56);
        for (int i = 0; i < 28; i++) {
            result.set(i + 28, c.get(i));
            result.set(i, d.get(i));
        }
        return result;
    }

    private BitSet createKey(BitSet cd) {
        BitSet result = new BitSet(48);
        for (int i = 0; i < 48; i++) {
            result.set(i, cd.get(IP[i] - 1));
        }
        return result;
    }

    public static BitSet generateKey() {

        BitSet key = new BitSet(64);

        for (int i = 0; i < 8; i++) {
            int counter = 0;
            for (int j = 0; j < 7; j++) {
                boolean value = 0.5 < Math.random();
                key.set(8 * i + j, value);
                counter += value ? 1 : 0;
            }
            key.set(8 * i + 7, counter % 2 == 0);
        }

        return key;
    }
}
