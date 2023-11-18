package joey.passwordencryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class PasswordEncryption {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter your password: ");
        String password = scanner.nextLine();

        // Scramble the password
        String scrambledPassword = hashPassword(password);

        System.out.println("Original Password: " + password);
        System.out.println("Scrambled Password: " + scrambledPassword);

        scanner.close();
    }

    public static String hashPassword(String password) {
        try {
            // Generate a salt value using SecureRandom
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);

            // Concatenate the password and salt
            byte[] passwordWithSalt = concatenateByteArrays(password.getBytes(), salt);

            // Use SHA-256 algorithm for hashing
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = messageDigest.digest(passwordWithSalt);

            // Convert the hashed password to a hexadecimal string
            StringBuilder hexStringBuilder = new StringBuilder();
            for (byte b : hashedPassword) {
                hexStringBuilder.append(String.format("%02x", b));
            }

            // Concatenate the salt and hashed password for storage
            return bytesToHex(salt) + ":" + hexStringBuilder.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            hexStringBuilder.append(String.format("%02x", b));
        }
        return hexStringBuilder.toString();
    }
}