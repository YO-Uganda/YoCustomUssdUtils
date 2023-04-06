import yocustomussdutil.YoCustomUssdUtilSignatureVerifier;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class TestYoCustomUssdUtils {

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        String publicKeyFile = "keys\\Yo_Custom_USSD_Public_key.pem";
        String datetime = "20230406090115";
        String anumbermsisdn = "256780349926";
        String data = datetime+anumbermsisdn;


        String sha1Data = YoCustomUssdUtilSignatureVerifier.getSha1HexaString(data);
        System.out.print(sha1Data);

        String signature = "ZrhJJ9sye/sIljNiwjK8MfIuAk+XMjKZ0Y0i9MU9PV5tL70wYS1JOx9G9nI3MvybYJ56c2TqZg99vP0SABNxWMstt7tnSHbSNgcPUtK0O5naW4hBVCKkiMIcBgJ+3zQJqDaX2d7R+KCiM9aqZN5ntwwoUm7hSrG2LbfDvnZBHGh2vKFqQZviZuwiSOEYjq85dkqZhFod09vi7VubgKCWKvZenoaR6WkY5Z+QOeU38tJ9g8tMt7wy/DExmw4lVy5QTH9RbF+viClgiuWPSyPR3vQ63p2J3cpOoh0sAsX7ininzZIC5iwl4If2X8KjmV+TP3FLWJTKFULmunDRFj1UyQ==";

        YoCustomUssdUtilSignatureVerifier verifier = new YoCustomUssdUtilSignatureVerifier(publicKeyFile);

        if (verifier.verifySignature(signature, sha1Data.getBytes())) {
            System.out.print("Verification was a success");

        } else {

            System.out.print("Verification failed");
            System.out.print(verifier.error);

        }
    }
}
