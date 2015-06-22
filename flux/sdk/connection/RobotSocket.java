package flux.sdk.connection;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;

import flux.sdk.util.Encryptor;
import flux.sdk.util.PyArr;
import flux.sdk.util.Logger;

public class RobotSocket{
    SecureSocket sock;
    public static RobotSocket connect(String addr) throws Exception{
        Socket sock = new Socket();
        sock.connect(new InetSocketAddress(addr,23811));
        InputStream is = sock.getInputStream();
        byte[] header = new byte[8];
        is.read(header,0,8);
        Logger.d("Connecting FLUX header / "+ new String(header));
        return new RobotSocket(sock);
    }
    public RobotSocket(Socket handshake_socket){
        try {
            handshake_socket.setSoTimeout(10000);
            InputStream handshake_in = handshake_socket.getInputStream();
            OutputStream handshake_out = handshake_socket.getOutputStream();
            byte[] buff = new byte[4096];
            handshake_in.read(buff,0,4096);
            buff = PyArr.stripZero(buff);
            byte[] sign = PyArr.get(buff, 8, -128);
            byte[] randbytes = PyArr.get(buff, -128, 0);

            KeyPair rsakey = Encryptor.get_or_create_keyobj();
            Logger.d("Protocol: FLUX0002 "+buff.length+","+randbytes.length);
            Logger.d("Access ID: " + Encryptor.get_access_hex(rsakey.getPublic()));

            byte[] buf = PyArr.concat(Encryptor.get_access_id(rsakey.getPublic()), Encryptor.sign(rsakey.getPrivate(), randbytes));
            handshake_out.write(buf);
            handshake_out.flush();
            byte[] status_raw = new byte[16];
            handshake_in.read(status_raw, 0, 16);
            String status = new String(PyArr.stripZero(status_raw));
            Logger.d("Status "+status);
            if (status.startsWith("OK")) {
                Logger.d("Handshake success.");
                byte[] aes_enc_init = new byte[128];
                handshake_in.read(aes_enc_init, 0, 128);
                byte[] aes_init = Encryptor.rsa_decrypt((RSAPrivateKey)(rsakey.getPrivate()), aes_enc_init);
                this.sock = new SecureSocket(handshake_socket, PyArr.get(aes_init, 0, 32), PyArr.get(aes_init, 32, 48));
                this.onInit();
            } else {
                throw new Exception("Handshake failed:" + status);
            }
        }catch(Exception e){
            e.printStackTrace();
            Logger.e("RobotSocket init error " + e.toString());
        }
    }

    void onInit() throws Exception{
        String resp = makeCmd("raw".getBytes());
        Logger.d("Welcome to the new world.." + resp);
    }

    private void sendCmd(byte[] buf) throws Exception{
        int l = buf.length;
        byte[] pad = new byte[(256 - (l % 128)) % 128];
        sock.send(PyArr.concat(buf,pad));
    }

    String getResponse() throws Exception{
        byte[] buf = new byte[128];
        this.sock.recv(buf, 128);
        return new String(PyArr.stripZero(buf),"UTF8");
    }

    private String makeCmd(byte[] buf) throws Exception{
        this.sendCmd(buf);
        return this.getResponse();
    }

}
