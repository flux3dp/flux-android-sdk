package flux.sdk.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import flux.sdk.util.Encryptor;
import flux.sdk.util.Logger;

/**
 * Created by simon on 15/6/20.
 */
public class SecureSocket{

    Cipher encoder, decoder;
    InputStream in;
    OutputStream out;
    Socket sock;
    byte[] aes_key;
    byte[] aes_iv;
    public SecureSocket(Socket socket, byte[] key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
        this.sock = socket;
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        IvParameterSpec iv_spec = new IvParameterSpec(iv);
        this.encoder = Cipher.getInstance("AES/CFB8/NoPadding");
        this.decoder = Cipher.getInstance("AES/CFB8/NoPadding");
        encoder.init(Cipher.ENCRYPT_MODE, spec, iv_spec);
        decoder.init(Cipher.DECRYPT_MODE, spec, iv_spec);
        aes_key = key;
        aes_iv = iv;
        in = this.sock.getInputStream();
        out = this.sock.getOutputStream();
    }

    public void recv(byte[] buff, int size) throws Exception{
        recv(buff,size, 0);
    }

    public void recv(byte[] buff, int size, int flag) throws Exception{
        in.read(buff, 0, size);
        Logger.d("Recv "+size+" bytes " + new String(Encryptor.bytesToHex(decoder.doFinal(buff, 0, size))));
        System.arraycopy(decoder.doFinal(buff, 0, size), 0, buff, 0, size);
    }

    public void send(byte[] buff) throws Exception{
        send(buff, buff.length);
    }

    public void send(byte[] buff, int size) throws Exception{
        out.write(encoder.doFinal(buff, 0, size));
    }


}
