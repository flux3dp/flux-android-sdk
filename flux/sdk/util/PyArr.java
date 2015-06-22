package flux.sdk.util;

/**
 * Created by simon on 15/6/20.
 */
public class PyArr{
    byte[] arr;

    public PyArr(byte[] arr){
        this.arr = arr;
    }

    public byte[] get(int start, int end){
        if(start<0) start = arr.length+start;
        if(end<=0) end = arr.length+end;
        byte[] result = new byte[end-start];
        for(int i = start; i < end; i++){
            result[i-start] = arr[i];
        }
        return result;
    }

    public static byte[] get(byte[] a, int start, int end){
        return new PyArr(a).get(start,end);
    }

    public static byte[] concat(byte[] a, byte[] b){
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static int index(byte[] a, byte c){
        for(int i = 0; i < a.length; i++){
            if(a[i]==c){
                return i;
            }
        }
        return -1;
    }

    public static byte[] stripZero(byte[] raw){
        if(raw.length==0) return raw;
        int i = raw.length-1;
        for(; i>=0 && raw[i]==0; i--);
        i = i+1;
        byte[] c = new byte[i];
        System.arraycopy(raw,0,c,0,i);
        return c;
    }
}
