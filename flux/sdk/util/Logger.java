package flux.sdk.util;

import android.util.Log;

/**
 * Created by simon on 15/6/20.
 */
public class Logger {
    public static void e(String msg){
        Log.e("TM", msg);
    }

    public static void d(String msg){
        Log.d("TM", msg);
    }
}
