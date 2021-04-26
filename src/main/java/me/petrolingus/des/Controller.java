package me.petrolingus.des;

import javafx.scene.control.TextArea;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Controller {

    public TextArea plainTextArea;
    public TextArea cipherTextArea;
    public TextArea keyTextArea;

    public void initialize() {
    }

    public void onGenerateKeyButton() {
        keyTextArea.setText(Base64.getEncoder().encodeToString(Keygen.generateKey().toByteArray()));
    }

    public void onEncodeButton() {

        // Получаем байты из исходного текста
        byte[] bytes = plainTextArea.getText().getBytes(StandardCharsets.UTF_8);

        // Создаем лист в котором будут хранится блоки для последущего шифрования
        List<BitSet> blocks = new ArrayList<>();

        // Разделяем массив байт на блоки по 8 байт и добаляем в blocks
        for (int i = 0; i < bytes.length / 8; i++) {
            byte[] block = new byte[8];
            System.arraycopy(bytes, i * 8, block, 0, 8);
            blocks.add(BitSet.valueOf(block));
        }

        // Добавляем оставшиеся биты, если они есть
        if (bytes.length % 8 != 0) {
            byte[] block = new byte[8];
            System.arraycopy(bytes, bytes.length - (bytes.length % 8), block, 0, bytes.length % 8);
            blocks.add(BitSet.valueOf(block));
        }

        // Создаем обьект для генераии ключей
        Keygen keygen = new Keygen(keyTextArea.getText());

        BitSet cipherBits = new BitSet();

        int blocksCounter = 0;

        // Шифруем блоки из blocks
        for (BitSet bitSet : blocks) {
            BitSet cipherBlock = encrypt(bitSet, keygen);
            for (int i = 0; i < 64; i++) {
                cipherBits.set(i + 64 * blocksCounter, cipherBlock.get(i));
            }
            blocksCounter++;
        }

        // Выводим зашифрованную последовательность байт в кодировке Base64
        byte[] encode = Base64.getEncoder().encode(cipherBits.toByteArray());
        cipherTextArea.setText(new String(encode));
    }

    public void onDecodeButton() throws IOException {

        byte[] cipherBytes = Base64.getDecoder().decode(plainTextArea.getText().getBytes(StandardCharsets.UTF_8));
        System.out.println(Arrays.toString(cipherBytes));
        System.out.println(cipherBytes.length);

        List<BitSet> blocks = new ArrayList<>();

        File encryptBlocks = new File("C:\\Users\\Petrolingus\\Desktop\\encryptBlocks2.txt");
        FileWriter writer = new FileWriter(encryptBlocks);

        for (int i = 0; i < cipherBytes.length / 8; i++) {
            byte[] block = new byte[8];
            System.arraycopy(cipherBytes, i * 8, block, 0, 8);
            BitSet bitSet = BitSet.valueOf(block);
            blocks.add(bitSet);
            writer.write(bitSet + "\n");
        }

        writer.close();

        // Создаем обьект для генераии ключей
        Keygen keygen = new Keygen(keyTextArea.getText());

        List<Byte> decipherBytesArray = new ArrayList<>();

        for (BitSet bitSet : blocks) {
            BitSet cipherBlock = decrypt(bitSet, keygen);
            for (Byte b : cipherBlock.toByteArray()) {
                decipherBytesArray.add(b);
            }
        }

        // Получаем массив типа byte из листа cipherBytesArray
        byte[] decipherBytes = new byte[decipherBytesArray.size()];
        for (int i = 0; i < decipherBytes.length; i++) {
            decipherBytes[i] = decipherBytesArray.get(i);
        }

        // Выводим зашифрованную последовательность байт в кодировке Base64
        cipherTextArea.setText(new String(decipherBytes));
    }

    /**
     * Encrypt the passed 65 bits block
     * @param plainBits bits of message data
     * @param keygen contain Keygen object with keys
     * @return cipher 64 bits block
     */
    private static BitSet encrypt(BitSet plainBits, Keygen keygen) {

        // Начальная перестановка
        BitSet initialPermutedBits = permuteBits(plainBits, Utils.IP);

        // Делим начальный набор битов на две половины
        BitSet rightBits = initialPermutedBits.get(0, 32);
        BitSet leftBits = initialPermutedBits.get(32, 64);

        for (int i = 0; i < 16; i++) {
            leftBits.xor(f(rightBits, keygen.getKey(i)));
            BitSet rightBits2 = BitSet.valueOf(leftBits.toByteArray());
            BitSet leftBits2 = BitSet.valueOf(rightBits.toByteArray());
            rightBits = rightBits2;
            leftBits = leftBits2;
        }

        BitSet result = combineBitSets(leftBits, rightBits);

        return permuteBits(result, Utils.IIP);
    }

    private static BitSet decrypt(BitSet cipherBits, Keygen keygen) {

        // Начальная перестановка
        BitSet initialPermutedBits = permuteBits(cipherBits, Utils.IP);

        // Делим начальный набор битов на две половины
        BitSet rightBits = initialPermutedBits.get(0, 32);
        BitSet leftBits = initialPermutedBits.get(32, 64);

        for (int i = 15; i >= 0; i--) {
            BitSet rightBits2 = BitSet.valueOf(leftBits.toByteArray());
            rightBits.xor(f(leftBits, keygen.getKey(i)));
            BitSet leftBits2 = BitSet.valueOf(rightBits.toByteArray());
            rightBits = rightBits2;
            leftBits = leftBits2;
        }

        BitSet result = combineBitSets(leftBits, rightBits);

        return permuteBits(result, Utils.IIP);
    }

    private static BitSet permuteBits(BitSet bitSet, int[] permutations) {
        BitSet result = new BitSet(64);
        for (int i = 0; i < 64; i++) {
            result.set(i, bitSet.get(permutations[i] - 1));
        }
        return result;
    }

    private static BitSet f(BitSet rightBitSet, BitSet key) {

        BitSet expendedRight = new BitSet(48);
        for (int i = 0; i < 48; i++) {
            expendedRight.set(i, rightBitSet.get(Utils.E[i] - 1));
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

            byte value = (byte) (Utils.bigTable[7 - i][row][column]);
            BitSet result = BitSet.valueOf(new byte[]{value});

            for (int j = 0; j < 4; j++) {
                temp.set(4 * i + j, result.get(j));
            }
        }

        BitSet result = new BitSet(32);
        for (int i = 0; i < 32; i++) {
            result.set(i, temp.get(Utils.P[i] - 1));
        }

        return result;
    }

    private static BitSet combineBitSets(BitSet leftBits, BitSet rightBits) {
        BitSet result = new BitSet(64);
        for (int i = 0; i < 32; i++) {
            result.set(i, rightBits.get(i));
            result.set(i + 32, leftBits.get(i));
        }
        return result;
    }

}
