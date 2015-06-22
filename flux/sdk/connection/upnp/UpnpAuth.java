package flux.sdk.connection.upnp;

import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.Date;

import flux.sdk.connection.RobotSocket;
import flux.sdk.util.Encryptor;
import flux.sdk.util.Logger;
import flux.sdk.util.PyArr;

/**
 * Created by simon on 15/6/21.
 */
public class UpnpAuth extends UpnpBase {

    final char CODE_PWD_ACCESS = 0x06;
    final char CODE_RESPONSE_PWD_ACCESS = 0x07;
    String passwd;

    public UpnpAuth(String serial, String password) throws Exception {
        super(serial);
        this.passwd = password;
    }

    public JSONObject auth(String passwd) throws Exception{
        byte[] der = Encryptor.exportDer(this.key.getPublic());
        ByteBuffer bb = ByteBuffer.allocate(4096);
        bb.put(("" + new Date().getTime()).getBytes());
        bb.put((byte)0);
        bb.put(passwd.getBytes());
        bb.put((byte)0);
        bb.put(der);
        JSONObject resp = this.makeRequest(CODE_PWD_ACCESS, CODE_RESPONSE_PWD_ACCESS, PyArr.get(bb.array(), 0, bb.position()));
        Logger.d("Upnp Auth resp "+resp.toString());
        RobotSocket.connect(remote_addr.getHostName());
        return resp;
    }

    @Override
    void onInit() throws Exception{
        super.onInit();
        auth(passwd);
    }
}
