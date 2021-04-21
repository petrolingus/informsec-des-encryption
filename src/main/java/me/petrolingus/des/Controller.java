package me.petrolingus.des;

import javafx.scene.control.TextArea;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.BitSet;
import java.util.List;

public class Controller {

    public TextArea plainTextArea;

    public TextArea cipherTextArea;

    public TextArea keyTextArea;

    private BitSet key;

    public void initialize() {
        onGenerateKeyButton();
    }

    public void onGenerateKeyButton() {
        key = generateKey();
        keyTextArea.setText(Base64.getEncoder().encodeToString(key.toByteArray()));
    }

    public void onEncodeButton() {

        byte[] bytes = plainTextArea.getText().getBytes(StandardCharsets.UTF_8);

        List<BitSet> plainBitSet = new ArrayList<>();

        for (int i = 0; i < bytes.length / 8; i++) {
            byte[] rowBytes = new byte[8];
            System.arraycopy(bytes, i * 8, rowBytes, 0, 8);
            plainBitSet.add(BitSet.valueOf(rowBytes));
        }
        byte[] rowBytes = new byte[8];
        System.arraycopy(bytes, 8 * (bytes.length / 8), rowBytes, 0, bytes.length % 8);
        plainBitSet.add(BitSet.valueOf(rowBytes));

        System.out.println(plainBitSet);

        StringBuilder stringBuilder = new StringBuilder();
        for (BitSet bitSet : plainBitSet) {
            stringBuilder.append(Base64.getEncoder().encodeToString(encrypt(bitSet).toByteArray()));
        }

        cipherTextArea.setText(stringBuilder.toString());
    }

    public void onDecodeButton() {

        String text = plainTextArea.getText();

        List<BitSet> cipherBitSet = new ArrayList<>();

        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            stringBuilder.append(ch);
            if (ch == '=') {
                cipherBitSet.add(BitSet.valueOf(Base64.getDecoder().decode(stringBuilder.toString())));
                stringBuilder = new StringBuilder();
            }
        }

        System.out.println(cipherBitSet);

        StringBuilder builder = new StringBuilder();
        for (BitSet bitSet : cipherBitSet) {
            builder.append(new String(decode(bitSet).toByteArray()));
        }

        cipherTextArea.setText(builder.toString());
    }

    public void onInputChangeKeyTextArea() {
        System.out.println("Key was changed");
        key = BitSet.valueOf(Base64.getDecoder().decode(keyTextArea.getText()));
    }

    private BitSet decode(BitSet bitSet) {

        // Начальная перестановка
        BitSet initialPermutationBitSet = new BitSet(64);
        for (int i = 0; i < 64; i++) {
            initialPermutationBitSet.set(i, bitSet.get(Utils.IP[i]));
        }

        // Делим начальный набор битов на две половины
        BitSet rightBitSet = initialPermutationBitSet.get(0, 32);
        BitSet leftBitSet = initialPermutationBitSet.get(32, 64);

        for (int i = 15; i >= 0; i--) {
            BitSet buffer = BitSet.valueOf(rightBitSet.toByteArray());
            leftBitSet.xor(f(rightBitSet, getKey(i)));
            rightBitSet = BitSet.valueOf(leftBitSet.toByteArray());
            leftBitSet = BitSet.valueOf(buffer.toByteArray());
        }

        BitSet lr = new BitSet(64);
        for (int i = 0; i < 32; i++) {
            lr.set(i + 32, rightBitSet.get(i));
            lr.set(i, leftBitSet.get(i));
        }

        BitSet result = new BitSet(64);
        for (int i = 0; i < 64; i++) {
            result.set(i, lr.get(Utils.IIP[i]));
        }

        return result;
    }

    private BitSet encrypt(BitSet bitSet) {

        // Начальная перестановка
        BitSet initialPermutationBitSet = new BitSet(64);
        for (int i = 0; i < 64; i++) {
            initialPermutationBitSet.set(i, bitSet.get(Utils.IP[i]));
        }

        // Делим начальный набор битов на две половины
        BitSet rightBitSet = initialPermutationBitSet.get(0, 32);
        BitSet leftBitSet = initialPermutationBitSet.get(32, 64);

        for (int i = 0; i < 16; i++) {
            BitSet buffer = BitSet.valueOf(rightBitSet.toByteArray());
            leftBitSet.xor(f(rightBitSet, getKey(i)));
            rightBitSet = BitSet.valueOf(leftBitSet.toByteArray());
            leftBitSet = BitSet.valueOf(buffer.toByteArray());
        }

        BitSet lr = new BitSet(64);
        for (int i = 0; i < 32; i++) {
            lr.set(i + 32, rightBitSet.get(i));
            lr.set(i, leftBitSet.get(i));
        }

        BitSet result = new BitSet(64);
        for (int i = 0; i < 64; i++) {
            result.set(i, lr.get(Utils.IIP[i]));
        }

        return result;
    }

    private BitSet f(BitSet right, BitSet key) {

        BitSet expendedRight = new BitSet(48);
        for (int i = 0; i < 48; i++) {
            expendedRight.set(i, right.get(Utils.E[i]));
        }

        expendedRight.xor(key);

        BitSet temp = new BitSet(32);
        for (int i = 0; i < 8; i++) {

            int id = 6 * i;
            BitSet sixBitsBlock = expendedRight.get(id, id + 6);

            BitSet twoBitsBlock = new BitSet(2);
            twoBitsBlock.set(0, sixBitsBlock.get(0));
            twoBitsBlock.set(1, sixBitsBlock.get(5));
            int row = (twoBitsBlock.length() == 0) ? 0 : twoBitsBlock.toByteArray()[0];

            BitSet fourBitsBlock = sixBitsBlock.get(1, 5);

            int column = (fourBitsBlock.length() == 0) ? 0 : fourBitsBlock.toByteArray()[0];

            byte value = (byte)(Utils.bigTable[7 - i][row][column]);
            BitSet result = BitSet.valueOf(new byte[]{value});

            for (int j = 0; j < 4; j++) {
                temp.set(4 * i + j, result.get(j));
            }
        }

        BitSet result = new BitSet(32);
        for (int i = 0; i < 32; i++) {
            result.set(i, temp.get(Utils.P[i]));
        }

        return result;
    }

    private BitSet getKey(int shiftId) {

        BitSet c = new BitSet(28);
        for (int i = 0; i < 28; i++) {
            int id = (i + Utils.S[shiftId]) % 28;
            c.set(i, key.get(Utils.C_ZERO[id]));
        }

        BitSet d = new BitSet(28);
        for (int i = 0; i < 28; i++) {
            int id = (i + Utils.S[shiftId]) % 28;
            d.set(i, key.get(Utils.D_ZERO[id]));
        }

        BitSet cd = new BitSet(56);
        for (int i = 0; i < 28; i++) {
            cd.set(i, d.get(i));
            cd.set(i + 28, c.get(i));
        }

        BitSet result = new BitSet(48);
        for (int i = 0; i < 48; i++) {
            result.set(i, cd.get(Utils.IP_KEY[i]));
        }

        return result;
    }

    private BitSet generateKey() {

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
