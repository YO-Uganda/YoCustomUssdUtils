package yocustomussdutil;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class YoCustomUssdUtilSignatureVerifier {

    public String error = "";
    public String algorithm = "SHA1withRSA";
    public String publicKeyFilePath = "";

    public YoCustomUssdUtilSignatureVerifier(String publicKeyFilePath) {
        this.publicKeyFilePath = publicKeyFilePath;
    }

    /*
     *
     * @Param signature:    This is the base64 encoded signature.
     * @Param data:         This is the data to be verified.
     *
     * Returns boolean      True if the signature verification is successful
     *                      or false otherwise.
     */
    public boolean verifySignature(String signature, byte[] data) {
        Signature sign = null;
        try {
            sign = Signature.getInstance(algorithm);

            PublicKey publicKey = getPublicKeyFromPemFile();
            if (publicKey == null) {
                return false;
            }

            sign.initVerify(publicKey);
            sign.update(data);

            byte[] signatureContent;
            signatureContent = Base64.getDecoder().decode(signature);

            if (!sign.verify(signatureContent)) {
                error = "Signature verification failed";
                return false;
            }

            return true;

        } catch (NoSuchAlgorithmException ex) {
            error = ex.getMessage();
        } catch (InvalidKeyException ex) {
            error = ex.getMessage();
            return false;
        } catch (SignatureException ex) {
            error = ex.getMessage();
            return false;
        }
        return false;
    }

    public PublicKey getPublicKeyFromPemFile() {
        try {
            String base64String = new String(
                    Files.readAllBytes(Paths.get(publicKeyFilePath)),
                    StandardCharsets.UTF_8
            );

            base64String = base64String.replace("-----BEGIN PUBLIC KEY-----\n", "");
            String base64Cleaned = base64String.replace("\n-----END PUBLIC KEY-----\n", "");



            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(
                    Base64.getMimeDecoder().decode(base64Cleaned)
            );
            RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

            return pubKey;

        } catch (IOException e) {
            //throw new RuntimeException(e);
            this.error = e.getMessage();
            return null;
        } catch (NoSuchAlgorithmException ex) {
            error = ex.getMessage();
            return null;
        } catch (InvalidKeySpecException ex) {
            error = ex.getMessage();
            return null;
        }
    }

    public static String getSha1HexaString(String data) {
        MessageDigest encode = null;
        try {
            encode = MessageDigest.getInstance("SHA-1");

            encode.reset();
            encode.update(data.getBytes("UTF-8"));
            byte[] sha1 = encode.digest();
            return byteToHex(sha1);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String byteToHex(final byte[] hash)
    {
        Formatter formatter = new Formatter();
        for (byte b : hash)
        {
            formatter.format("%02x", b);
        }
        String result = formatter.toString();
        formatter.close();
        return result;
    }

}
