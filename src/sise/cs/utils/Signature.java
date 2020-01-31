package sise.cs.utils;

import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Signature {

    // create method to create a digital signature
    //msg --> message to hash
    // FileToRead --> directory with the privateKey of the user
    public String[] sign(String msg, String FileToReadPrivKey) throws Exception {

        // create a Hash of the message
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash = Base64.getEncoder().encodeToString(digest.digest(msg.getBytes("UTF-8")));

        // Encrypt hash with the private key
        AsymEncryptPriv ac = new AsymEncryptPriv();
        PrivateKey privateKey = ac.getPrivate(FileToReadPrivKey); // get private key from directory
        String encrypted_hash = ac.encryptText(hash, privateKey);

        //slide 57
        return new String[] {msg, encrypted_hash};
    }

    public boolean verify(String FileToReadPubkey, String msg, String encrypted_hash) throws Exception {
        // Create a hash of the message we want to compare
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash_to_compare = Base64.getEncoder().encodeToString(digest.digest(msg.getBytes("UTF-8")));

        ////decrypt message
        AsymDecryptPub ad = new AsymDecryptPub();
        PublicKey publicKey = ad.getPublic(FileToReadPubkey);
        String decrypted_hash = ad.decryptText(encrypted_hash, publicKey);

        //Compare
        return hash_to_compare.equals(decrypted_hash);
    }
}
