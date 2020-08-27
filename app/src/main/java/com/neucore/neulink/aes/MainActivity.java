package com.neucore.neulink.aes;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import java.util.Properties;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("AesUtil");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);

        String plain = "FTP.Server=ftp://10.18.105.254:21;\n" +
                "Topic.Partition=ftproot;\n" +
                "FTP.UserName=neu2ftp;\n" +
                "MQTT-Server=tcp://mqtt.neucore.com:1883;\n" +
                "FTP.Password=123456;\n" +
                "Storage.Type=OSS;\n" +
                "OSS.AccessKeySecret=fJPkLrpdMRIEB6BxdwbpD1xJsivC9h;\n" +
                "OSS.AccessKeyID=LTAI4G6ZyiqBdrY9HA1Np6To;\n" +
                "OSS.BucketName=neudevice;\n" +
                "OSS.EndPoint=https://oss-cn-shanghai.aliyuncs.com;\n" +
                "FTP.BucketName=ftproot;\n" +
                "Log.Level=W;\n";
        plain = "java1111111111111212121212123232323212121212121212121java1111111111111212121212123232323212121212121212121java1111111111111212121212123232323212121212121212121";
        System.out.println(plain);
        String enc = AesUtil.encrypt(plain);
        System.out.println(enc);
        String plain_ = AesUtil.decrypt(enc);
        System.out.println(plain_);

        tv.setText(plain_);
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
