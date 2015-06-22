package flux.sdk.util;

import android.util.Base64;

import org.json.JSONObject;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

import javax.crypto.Cipher;


/**
 * Created by simon on 15/6/20.
 */
public class Encryptor {

    public static Key loadPem(String pem) throws Exception{
        return loadPem_public(pem);
    }
    public static PublicKey loadPem_public(String pem) throws Exception {
        String key = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("\"", "").replace("\"","");
        key = key.replace("-----END PUBLIC KEY-----", "").replace("\n", "").replace("\n", "").replace("\n", "").replace("\n", "").replace("\n", "").replace("\\n", "").replace("\\n", "").replace("\\n", "").replace("\\n","").replace("\\n","").replace("\\n","").replace("\\n","");
        System.out.println("Public key = " + key);

        byte [] encoded = Base64.decode(key, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }

    public static PrivateKey loadPem_private(String pem) throws Exception {
        String key = pem.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("\"", "").replace("\"","");
        key = key.replace("-----END RSA PRIVATE KEY-----", "").replace("\n", "").replace("\n", "").replace("\n", "").replace("\n", "").replace("\n", "").replace("\\n", "").replace("\\n", "").replace("\\n", "").replace("\\n","").replace("\\n","").replace("\\n","").replace("\\n","");
        System.out.println("RSA Private key = " + key);

        byte[] encoded = Base64.decode(key, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return kf.generatePrivate(keySpec);
    }

    public static byte[] exportDer(PublicKey key) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key.getEncoded());
        return x509EncodedKeySpec.getEncoded();
    }

    public static String exportPem(PublicKey key) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key.getEncoded());
        String buff = "-----BEGIN PUBLIC KEY-----\n$\n-----END PUBLIC KEY-----\n";
        String b64 = Base64.encodeToString(x509EncodedKeySpec.getEncoded(), Base64.DEFAULT).replace("\n", "").replace("\n","").replace("\n","").replace("\n","").replace("\n","");
        Logger.d("raw b64 len = "+b64.length());
        String nb64 = "";
        for(int i = 0; i<b64.length(); i+=64) {
            if(i+64<b64.length()) {
                nb64 += b64.substring(i, i+64) + "\n";
            }else{
                nb64 = nb64 + b64.substring(i);
            }
        }
        String result = buff.replace("$", nb64);
        return result;
    }

    public static String exportPem(PrivateKey key) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key.getEncoded());
        String buff = "-----BEGIN RSA PRIVATE KEY-----\n$\n-----END RSA PRIVATE KEY-----\n";
        String b64 = Base64.encodeToString(spec.getEncoded(), Base64.DEFAULT).replace("\n", "").replace("\n","").replace("\n","").replace("\n","").replace("\n","");
        String nb64 = "";
        for(int i = 0; i<b64.length(); i+=64) {
            if(i+64<b64.length()) {
                nb64 += b64.substring(i, i+64) + "\n";
            }else{
                nb64 = nb64 + b64.substring(i);
            }
        }
        String result = buff.replace("$", nb64);
        return result;
    }

    public static KeyPair get_or_create_keyobj() throws Exception{
        return get_or_create_keyobj("/data/data/flux.apps.tm/fluxclient_key5.pem");
    }

    public static KeyPair get_or_create_keyobj(String filename) throws Exception {
        File f = new File(filename);
        File f2 = new File(filename+".pub");

        try {
            if(f.exists()) {
                DataInputStream din = new DataInputStream(new FileInputStream(f));
                byte[] private_pem = new byte[(int) f.length()];
                din.readFully(private_pem);
                din.close();

                DataInputStream din2 = new DataInputStream(new FileInputStream(f2));
                byte[] pub_pem = new byte[(int) f2.length()];
                din2.readFully(pub_pem);
                din2.close();

                PrivateKey privKey = loadPem_private(new String(private_pem));
                PublicKey pubKey = loadPem_public(new String(pub_pem));
                return new KeyPair(pubKey,privKey);
            }else{
                FileOutputStream fo = new FileOutputStream(f);
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                KeyPair kp = keyGen.genKeyPair();
                fo.write(exportPem(kp.getPrivate()).getBytes());
                fo.close();
                FileOutputStream fo2 = new FileOutputStream(f2);
                fo2.write(exportPem(kp.getPublic()).getBytes());
                fo2.close();
                return kp;
            }
        }catch(Exception e){
            e.printStackTrace();
            Logger.e("Private Key File error");
        }
        return null;
    }

    public static String rsa_test(RSAPublicKey pub, RSAPrivateKey priv, String msg) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] output = cipher.doFinal(msg.getBytes());
        Logger.d("Result = " +output.length + " bytes" );
        cipher.init(Cipher.DECRYPT_MODE, priv);
        return new String(cipher.doFinal(output));
    }

    public static byte[] rsa_encrypt(RSAPublicKey key, byte[] msg) throws Exception{

        Logger.d("Encrypting " + msg.length + " with key size " + key.getModulus().bitLength());
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        ByteBuffer bb = ByteBuffer.wrap(msg);
        int block_size = ((key.getModulus().bitLength() + 1) / 8) - 42;

        ByteBuffer out = ByteBuffer.allocate(4096);
        byte[] buf = new byte[block_size];
        while(bb.remaining()>=block_size) {
            bb.get(buf, 0, block_size);
            out.put(cipher.doFinal(buf));
        }
        bb.get(buf, 0, bb.remaining());
        out.put(cipher.doFinal(buf));
        byte[] result = PyArr.stripZero(out.array());
        Logger.d("Encrypted to "+ result.length +" bytes");
        return result;
    }

    public static byte[] rsa_decrypt(RSAPrivateKey key, byte[] msg) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);

        Logger.d("Decrypting " + msg.length + " bytes");
        return cipher.doFinal(msg);
//        ByteBuffer bb = ByteBuffer.wrap(msg);
//        int block_size = key.getModulus().bitLength()/8;
//
//        ByteBuffer out = ByteBuffer.allocate(4096);
//        byte[] buf = new byte[block_size];
//        while(bb.remaining()>=block_size) {
//            bb.get(buf, 0, block_size);
//            Logger.d("Chunk Size " + block_size);
//            System.out.println(bytesToHex(buf));
//            out.put(cipher.doFinal(buf));
//        }
//        byte[] bufend = new byte[bb.remaining()];
//        bb.get(bufend, 0, bb.remaining());
//        out.put(cipher.doFinal(bufend));
//        byte[] result = PyArr.stripZero(out.array());
//        Logger.d("Decrypted to "+result.length+"bytes");
//        System.out.println(bytesToHex(result));
//        return result;
    }


    public static int rsa_size() {
        return (1024 + 1) / 8;
    }


    void get_public_key_pem(KeyPair keyobj) throws Exception{

    }

    void get_public_key_der(KeyPair keyobj) throws Exception{
    }

    public static byte[] get_access_id(PublicKey key) throws Exception{
        String pem = exportPem(key);
        if(pem.charAt(pem.length()-1)!='\n') pem += '\n';
        JSONObject j = new JSONObject();
        j.put("test", pem);
        Logger.d("PEM OUTPUT " + j.toString()  + "___");
        MessageDigest md = null;
        md = MessageDigest.getInstance("SHA-1");
        return md.digest(pem.getBytes("UTF-8"));
    }

    public static String get_access_hex(PublicKey key) throws Exception {
        byte[] b = get_access_id(key);
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                    Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }

    public static byte[] sign(PrivateKey keyobj, byte[] message) throws Exception{
        Signature instance = Signature.getInstance("SHA1withRSA");
        instance.initSign(keyobj);
        instance.update(message);
        return instance.sign();
    }

    public static boolean validate_signature(PublicKey keyobj, byte[] message, byte[] signature) throws Exception{
        Signature instance = Signature.getInstance("SHA1withRSA");
        instance.initVerify(keyobj);
        instance.update(message);
        return instance.verify(signature);
    }

    static byte[] convertPublickPem(PublicKey key){
        //Todo implement this
        return new byte[1024];
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
