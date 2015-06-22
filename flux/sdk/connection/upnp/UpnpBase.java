package flux.sdk.connection.upnp;

import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Random;
import java.util.UUID;

import flux.sdk.util.Logger;
import flux.sdk.util.PyArr;
import flux.sdk.util.Encryptor;


/**
 * Created by simon on 15/6/20.
 */
public class UpnpBase {
    InetAddress ipaddr;
    int port;
    UUID serial;
    boolean _inited;
    KeyPair key;
    DatagramSocket sock;
    PublicKey remote_keyobj;
    UpnpDiscover discover_instance;
    InetAddress remote_addr;
    boolean has_password;
    String model_id, remote_version, access_id;
    Double timedelta;

    public UpnpBase(String serial) throws Exception {
        //lookup_callback=None;
        boolean forcus_broadcast = false;
        this.ipaddr = InetAddress.getByName("255.255.255.255");
        this.port = 3310;
        if (serial.length() == 25) {
            this.serial = UpnpMisc.short_to_uuid(serial);
        } else {
            this.serial = UpnpMisc.str_to_uuid(serial);
        }

        this.key = Encryptor.get_or_create_keyobj();//original keyobj
        this._inited = false;

        discover_instance = new UpnpDiscover();
        discover_instance.addListener(new PayloadListener());
        discover_instance.start();

        //TODO figure out forcus_broadcast implement..
//        if (!forcus_broadcast) {
//              for (InetAddress ipaddr :this.remote_addrs){
//                  discover_instance.addListener(new IpListener());
//                  discover_instance.ipaddr = ipaddr;
//                  discover_instance.start();
//              }
//        }
    }

    void onInit() throws Exception{
        Logger.d("Initiating upnp base");
        if (this.remote_version.compareTo("0.8a1") == -1) {
            throw new Exception("fluxmonitor version is too old");
        }
        this.sock = new DatagramSocket();
        this.sock.setBroadcast(true);
        this.sock.setSoTimeout(5000);
        this.fetchPublickey(3);
    }


    double createTimestemp() {
        return new Date().getTime() + this.timedelta;
    }

    JSONObject fetchPublickey(int retry) throws Exception{
        Logger.d("Fetching public key of "+UpnpMisc.uuid_to_short(this.serial));
        JSONObject resp = this.makeRequest(UpnpMisc.CODE_RSA_KEY,
                UpnpMisc.CODE_RESPONSE_RSA_KEY, "".getBytes());

        Logger.d("Response " + resp);
        if (resp != null) {
            return resp;
        } else if (retry > 0) {
            return this.fetchPublickey(retry - 1);
        } else {
            throw new Exception("Remote did not return public key");
        }
    }

    byte[] packRequest(byte req_code, byte[] message){
        ByteBuffer payload_gen = ByteBuffer.allocate(4+16+1);
        payload_gen.order(ByteOrder.LITTLE_ENDIAN);
        payload_gen.put("FLUX".getBytes());
        payload_gen.put(UpnpMisc.uuid_to_bytes(this.serial));
        payload_gen.put(req_code);
        return PyArr.concat(payload_gen.array(), message);
    }

    JSONObject makeRequest(char req_code, char resp_code, byte[] message) throws Exception{
        return makeRequest(req_code, resp_code, message, true, 1200);
    }
    JSONObject makeRequest(char req_code, char resp_code, byte[] message, boolean encrypt,
                           int timeout) throws Exception{
        if (message.length > 0 && encrypt) {
            message = Encryptor.rsa_encrypt((RSAPublicKey)this.remote_keyobj, message);
        }

        byte[] payload = packRequest((byte) req_code, message);

        byte[] recvBuf = new byte[1024];
        DatagramPacket recv_packet = new DatagramPacket(recvBuf, recvBuf.length);

        this.sock.setBroadcast(false);

        int retry = 3;

        while(retry>0) {
            try {
                DatagramPacket packet = new DatagramPacket(payload, payload.length, this.remote_addr, this.port);
                this.sock.send(packet);
                this.sock.receive(recv_packet);
                break;
            }catch(SocketTimeoutException e) {
                Logger.e("Timeout retry "+retry);
                retry--;
            }
        }

        return parseResponse(recv_packet.getData(), resp_code);
    }

    byte[] signRequest(byte[] body) throws Exception{
        Random r = new Random();
        byte[] salt = (""+(r.nextInt(9000)+1000)).getBytes();

        ByteBuffer meta_gen = ByteBuffer.allocate(20+4+4);
        meta_gen.order(ByteOrder.LITTLE_ENDIAN);
        meta_gen.put(this.access_id.getBytes());
        meta_gen.putFloat(new Date().getTime());
        meta_gen.put(salt);

        byte[] message = PyArr.concat(meta_gen.array(), body);

        byte[] signature = Encryptor.sign(key.getPrivate(), PyArr.concat(UpnpMisc.uuid_to_bytes(this.serial), message));

        return PyArr.concat(message, signature);
    }

    JSONObject parseResponse(byte[] buf, char resp_code) throws Exception{
        byte[] payload, signature;
        payload = PyArr.get(PyArr.stripZero(buf), 2, 0);
        signature = PyArr.get(payload, PyArr.index(payload,(byte)0)+1,0);
        payload = PyArr.get(payload, 0, PyArr.index(payload,(byte)0));
        int code = buf[0], status = buf[1];
        Logger.e("Resp code: "+ code + ", status: "+ status + ". Expecting "+ ((byte)resp_code));
        Logger.e("Payload: " + new String(payload));

        if (code != resp_code) return null;

        if (status != 0) throw new Exception(new String(payload,"utf8"));

        String payload_json = new String(payload, "UTF8");

        if (resp_code == UpnpMisc.CODE_RESPONSE_RSA_KEY) {
            remote_keyobj = Encryptor.loadPem_public(payload_json);
            if (Encryptor.validate_signature(remote_keyobj, payload, signature)) {
                JSONObject json = new JSONObject();
                json.put("data", payload_json);
                return json;
            } else {
                Logger.e("Upnp Base rsa validate error");
            }
        } else if (Encryptor.validate_signature(this.remote_keyobj, payload, signature)) {
            return new JSONObject(payload_json);
        }
        return null;
    }

    class PayloadListener implements UpnpDiscover.Listener {
        @Override
        public void onPayload(JSONObject json, String from) {
            try {
                Logger.d("My uuid = " + serial.toString());
                if (UpnpMisc.str_to_uuid(json.getString("serial")).equals(serial)) {
                    model_id = json.getString("model");
                    timedelta = json.getDouble("time") - new Date().getTime();
                    remote_version = json.getString("ver");
                    has_password = json.getBoolean("pwd");
                    remote_addr = InetAddress.getByName(json.getString("remote_addr"));
                    _inited = true;
                    discover_instance.stop();
                    onInit();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
