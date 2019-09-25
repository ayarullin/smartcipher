import javax.crypto.*;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {
    public static void main(String... args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        byte[] input = "Text for encrypt".getBytes();
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        SecureRandom random = new SecureRandom();

        String pbKey = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGC/5rhjzvMnhOHseHT5LvpcvAde" +
                "XFNQf5DWAXSZkUy69qnxhWcY1Ze4j6QLvmR6sSXFVKeZqqGFdaMlaMNdiNCq4XeN" +
                "5hVF35iMHKzaFA4nhavbBaD/yUPkfiWjbt7CnEq+un+gwQXK8VCIk0IHIL7qJlqM" +
                "PNMqDcdjB34tDeCTAgMBAAE=";
        byte[] sigBytes = Base64.getDecoder().decode(pbKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(sigBytes);
        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
        PublicKey pubKey = keyFact.generatePublic(x509KeySpec);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Base64.getEncoder().encodeToString(cipherText));

        String pvKey = "MIICXAIBAAKBgGC/5rhjzvMnhOHseHT5LvpcvAdeXFNQf5DWAXSZkUy69qnxhWcY" +
                "1Ze4j6QLvmR6sSXFVKeZqqGFdaMlaMNdiNCq4XeN5hVF35iMHKzaFA4nhavbBaD/" +
                "yUPkfiWjbt7CnEq+un+gwQXK8VCIk0IHIL7qJlqMPNMqDcdjB34tDeCTAgMBAAEC" +
                "gYANqy8Cf/9d9QheDtWZ2RadAnsCI3+xuZ68LK/59DRF/egZbGjnfue2TrnkeFBG" +
                "y9q5Nl7Wauxjc4KCMSfS6iUJAYmZlZ7IvXeNEl+4qYtGGRZc0DXoSFkiEZvYvB9e" +
                "V6faw6L8rPAfQGg6WpBDlnqrbgSB5Mv3ITbWGzyBa2sa8QJBAKQC5pKTvfRzHo9F" +
                "nwEYig3FmLAN0QNJ0SJxqgEewdkewH392ytsbDEyM/0q8cz+gAsa+AkufPx+O77K" +
                "pFXOpjsCQQCXA2s1GO6pFwbjTF3pPeIKh94fJF5e1UIvrbGFuKPddS2y59I4GBJU" +
                "AMixDEtI+VsGv/YezjGJ01vq8kOZdxGJAkEAitKpt4e2USLfywVzAMp0kBOgmeQX" +
                "9mCU1ELBUxFloxGUfRBSYv7y1PFZcADZilogp0W8jIj84fs3NtbvInI34QJBAInu" +
                "oXl6MGNZmPz7v7tOvqwHtaaUPW45M58A82jEYUfhw7/pZmW99t+rZ6PvKsSYnb/o" +
                "jhFNHIpa91X9uijuTKECQGcNw6lWbHXsMW1yXMN0MZKioRZ/ZDIBXalxDalxxz0t" +
                "976uDCVf8YZQ2jkH5EZiJePfmo3Si4lnoxTwua8jsq0=";

        sigBytes = Base64.getDecoder().decode(pvKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(sigBytes);
        keyFact = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privKey = keyFact.generatePrivate(keySpec);

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + new String(plainText));
    }
}
