package flux.sdk.connection.upnp;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import flux.sdk.util.LittleEndianDataInputStream;

public class UpnpDiscover {

    public interface Listener{
        void onPayload(JSONObject json, String from);
    }

    private List<Listener> listeners = new ArrayList<Listener>();
    Timer timer = new Timer("Ping timer");

    final short CODE_DISCOVER = 0x00;
    final short CODE_RESPONSE_DISCOVER = 0x01;

    DatagramSocket sock;
    byte[] discover_payload;
    int port;
    InetAddress ipaddr;

    public UpnpDiscover() throws Exception{
        this.ipaddr = InetAddress.getByName("255.255.255.255");
        this.port = 3310;
        this.sock = new DatagramSocket();
        this.sock.setBroadcast(true);
        this.sock.setSoTimeout(5000);
        // Generate discovering payload
        ByteBuffer payload_gen = ByteBuffer.allocate(4096);
        payload_gen.order(ByteOrder.LITTLE_ENDIAN);
        payload_gen.put("FLUX".getBytes());
        payload_gen.put("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes());
        payload_gen.putShort(CODE_DISCOVER);
        this.discover_payload = payload_gen.array();
    }

    public void start(){
        timer.scheduleAtFixedRate(new Poke(),0,3500);
    }

    public void stop(){
        timer.cancel();
    }

    private void waitResponse() throws IOException{
        byte[] recvBuf = new byte[4096];
        DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
        this.sock.receive(packet);
        parseResponse(packet);
    }

    private void parseResponse(DatagramPacket packet) throws IOException{
        InputStream raw_input = new ByteArrayInputStream(packet.getData());
        LittleEndianDataInputStream in = new LittleEndianDataInputStream(raw_input);
        int code = in.readUnsignedByte();
        int status = in.readUnsignedByte();
        byte[] payload_bytes = new byte[4096];
        try{
            in.readString(payload_bytes);
            String payload_json = new String(payload_bytes, "UTF8");
            payload_json = payload_json.replaceAll("\0","");
            JSONObject payload = new JSONObject(payload_json);
            payload.put("remote_addr", packet.getAddress().getHostAddress());
            if(code == CODE_RESPONSE_DISCOVER){
                payload.put("from_lan", true);
                onPayload(payload, "lan");
            }
                
        }catch(Exception e){
            e.printStackTrace();
            Log.d("TM", "Upnp discover response error: " + e.toString());
        }
    }

    public void ping() throws IOException{
        DatagramPacket packet = new DatagramPacket(discover_payload, discover_payload.length, this.ipaddr, this.port);
        this.sock.send(packet);
    }

    public void onPayload(JSONObject json, String from) {
        for (Listener l : listeners)
            l.onPayload(json, from);
    }

    public void addListener(Listener listener){
        listeners.add(listener);
    }

    class Poke extends TimerTask {
        @ Override
        public void run() {
            try {
                Log.d("TM", "Discover Ping");
                ping();
                waitResponse();
            }catch (SocketTimeoutException e){
                Log.e("TM", "Discover Ping timeout");
            }catch (Exception e){
                e.printStackTrace();
                Log.e("TM","Discover Ping error " + e.toString());
            }
        }
    }
}
