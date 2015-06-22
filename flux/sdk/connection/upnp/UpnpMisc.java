package flux.sdk.connection.upnp;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.UUID;


/**
 * Created by simon on 15/6/20.
 */
public class UpnpMisc {
    static final String HEXMAP = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static final int DEFAULT_PORT = 3310;

    public static final short CODE_DISCOVER = 0x00;
    public static final short CODE_RESPONSE_DISCOVER = 0x01;

    public static final char CODE_RSA_KEY = 0x02;
    public static final char CODE_RESPONSE_RSA_KEY = 0x03;

    public static final short CODE_NOPWD_ACCESS = 0x04;
    public static final short CODE_RESPONSE_NOPWD_ACCESS = 0x05;

    public static final short CODE_PWD_ACCESS = 0x06;
    public static final short CODE_RESPONSE_PWD_ACCESS = 0x07;

    public static final short CODE_CHANGE_PWD = 0x08;
    public static final short CODE_RESPONSE_CHANGE_PWD = 0x09;

    public static final short CODE_SET_NETWORK = 0x0a;
    public static final short CODE_RESPONSE_SET_NETWORK = 0x0b;

    public static byte[] uuid_to_bytes(UUID u){
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(u.getMostSignificantBits());
        bb.putLong(u.getLeastSignificantBits());
        return bb.array();
    }

    public static UUID str_to_uuid(String str){
        UUID uuid = new UUID(
                new BigInteger(str.substring(0, 16), 16).longValue(),
                new BigInteger(str.substring(16), 16).longValue());
        return uuid;
    }

    public static String uuid_to_short(UUID u) {
        String mapping = HEXMAP;
        BigInteger n = new BigInteger(uuid_to_bytes(u));
        BigInteger l = BigInteger.valueOf(mapping.length());
        String a = "";
        while(n.compareTo(BigInteger.ZERO) == 1) {
            char c = mapping.charAt(n.mod(l).intValue());
            n = n.divide(l);
            a += c;
        }

        while (a.length() < 25){
            a+= mapping.charAt(0);
        }

        return a;
    }

    public static UUID short_to_uuid(String abbr) {
        String mapping = HEXMAP;
        BigInteger n = BigInteger.valueOf(0);
        BigInteger offset = BigInteger.valueOf(1);
        BigInteger l = BigInteger.valueOf(mapping.length());

        for (int i = 0; i < abbr.length(); i++) {
            n = n.add(BigInteger.valueOf(mapping.indexOf(abbr.charAt(i))).multiply(offset));
            offset = offset.multiply(l);
        }

        ByteBuffer bb = ByteBuffer.wrap(n.toByteArray());
        long firstLong = bb.getLong();
        long secondLong = bb.getLong();
        return new UUID(firstLong, secondLong);
    }
}
