import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESUtil {
    // Debug flag
    private static boolean DEBUG = false;

    public static void setDebug(boolean debug) {
        DEBUG = debug;
    }

    public static String encrypt(String plaintext, String key, boolean useCBC) throws Exception {
        Cipher cipher;
        byte[] keyBytes = normalizeKey(key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        if (useCBC) {
            byte[] iv = generateIV();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

            if (DEBUG) printDebugInfo("ENCRYPT-CBC", plaintext.getBytes(), ciphertext, iv);

            // Prepend IV to ciphertext
            byte[] fullCipher = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, fullCipher, 0, iv.length);
            System.arraycopy(ciphertext, 0, fullCipher, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(fullCipher);
        } else {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

            if (DEBUG) printDebugInfo("ENCRYPT-ECB", plaintext.getBytes(), ciphertext, null);

            return Base64.getEncoder().encodeToString(ciphertext);
        }
    }

    public static String decrypt(String cipherTextBase64, String key, boolean useCBC) throws Exception {
        Cipher cipher;
        byte[] keyBytes = normalizeKey(key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        byte[] cipherBytes = Base64.getDecoder().decode(cipherTextBase64);

        if (useCBC) {
            byte[] iv = new byte[16];
            byte[] ciphertextOnly = new byte[cipherBytes.length - 16];
            System.arraycopy(cipherBytes, 0, iv, 0, 16);
            System.arraycopy(cipherBytes, 16, ciphertextOnly, 0, ciphertextOnly.length);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] plaintext = cipher.doFinal(ciphertextOnly);

            if (DEBUG) printDebugInfo("DECRYPT-CBC", ciphertextOnly, plaintext, iv);

            return new String(plaintext);
        } else {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] plaintext = cipher.doFinal(cipherBytes);

            if (DEBUG) printDebugInfo("DECRYPT-ECB", cipherBytes, plaintext, null);

            return new String(plaintext);
        }
    }

    // Pads or trims key to 16 bytes (128-bit AES)
    private static byte[] normalizeKey(String key) {
        byte[] keyBytes = new byte[16]; // AES-128
        byte[] rawKey = key.getBytes();
        int length = Math.min(rawKey.length, 16);
        System.arraycopy(rawKey, 0, keyBytes, 0, length);
        return keyBytes;
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[16]; // 16-byte IV for AES
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static void printDebugInfo(String label, byte[] input, byte[] output, byte[] iv) {
        System.out.println("---- DEBUG: " + label + " ----");
        if (iv != null) System.out.println("IV:        " + bytesToHex(iv));
        System.out.println("Input:     " + bytesToHex(input));
        System.out.println("Output:    " + bytesToHex(output));
        System.out.println("-------------------------------");
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data)
            sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    // Sample usage
    public static void main(String[] args) throws Exception {
        setDebug(true);

        String plaintext = "This is a test message.";
        String key = "password12345678";

        System.out.println("\nStarting Text: " + plaintext);
        
        System.out.println("\n----- ECB Mode -----");
        String encryptedECB = encrypt(plaintext, key, false);
        System.out.println("Encrypted: " + encryptedECB);
        String decryptedECB = decrypt(encryptedECB, key, false);
        System.out.println("Decrypted: " + decryptedECB);

        
        System.out.println("\n----- CBC Mode -----");
        String encryptedCBC = encrypt(plaintext, key, true);
        System.out.println("Encrypted: " + encryptedCBC);
        String decryptedCBC = decrypt(encryptedCBC, key, true);
        System.out.println("Decrypted: " + decryptedCBC);
    }
}
