package com.neucore.neulink.aes;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import java.util.Properties;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);

        System.err.println("========================================================================");
        String plain = "FTP.Server=ftp://1dd0.18.143s05.2dd54:21;\n" +
                "Topic.Partition=ftprofdaot;\n" +
                "FTP.UserName=neafu2fdafeftp;\n" +
                "MQTT-Server=tcp://mqtfdft.rerdeucorddade.cndfofda:212132;\n" +
                "FTP.Password=1234fdafd56;\n" +
                "Storage.Type=OSS;\n" +
                "OSS.AccessKeySecret=fJPkfdafdLrpdMRI中文🤮EB6BxdwbpDfdafd1xJsivC9h;\n" +
                "OSS.AccessKeyID=LTAI4G6ZyfdaiqBddfdarY9HA1Np6To;\n" +
                "OSS.BucketName=neudevice;\n" +
                "OSS.EndPoint=https://oss-cn-shanghai.aliyuncs.com;\n" +
                "FTP.BucketName=ftprfdofgadeot;\n" +
                "Log.Level=W;\n";

        System.out.println("origin: "+plain);
        System.err.println("========================================================================");

        System.out.println("trans: "+AesUtil.trans(plain));

        System.err.println("========================================================================");
        System.out.println("encrypt$decrypt: "+AesUtil.encrypt$decrypt(plain));
        System.err.println("========================================================================");
        //RlRQLlNlcnZlcj1mdHA6Ly8xMC4xOC4xMDUuMjU0OjIxOwpUb3BpYy5QYXJ0aXRpb249ZnRwcm9vdDsKRlRQLlVzZXJOYW1lPW5ldTJmdHA7Ck1RVFQtU2VydmVyPXRjcDovL21xdHQubmV1Y29yZS5jb206MTg4MzsKRlRQLlBhc3N3b3JkPTEyMzQ1NjsKU3RvcmFnZS5UeXBlPU9TUzsKT1NTLkFjY2Vzc0tleVNlY3JldD1mSlBrTHJwZE1SSUVCNkJ4ZHdicEQxeEpzaXZDOWg7Ck9TUy5BY2Nlc3NLZXlJRD1MVEFJNEc2WnlpcUJkclk5SEExTnA2VG87Ck9TUy5CdWNrZXROYW1lPW5ldWRldmljZTsKT1NTLkVuZFBvaW50PWh0dHBzOi8vb3NzLWNuLXNoYW5naGFpLmFsaXl1bmNzLmNvbTsKRlRQLkJ1Y2tldE5hbWU9ZnRwcm9vdDsKTG9nLkxldmVsPVc7Cg..
        String encBase64 = AesUtil.encBase64(plain);
        System.out.println("base640: "+encBase64);
        System.err.println("========================================================================");
        String enc = AesUtil.encrypt(plain);
        System.out.println("Enc: "+enc);

        //UmxSUUxsTmxjblpsY2oxbWRIQTZMeTh4TUM0eE9DNHhNRFV1TWpVME9qSXhPd3BVYjNCcFl5NVFZWEowYVhScGIyNDlablJ3Y205dmREc0tSbFJRTGxWelpYSk9ZVzFsUFc1bGRUSm1kSEE3Q2sxUlZGUXRVMlZ5ZG1WeVBYUmpjRG92TDIxeGRIUXVibVYxWTI5eVpTNWpiMjA2TVRnNE16c0tSbFJRTGxCaGMzTjNiM0prUFRFeU16UTFOanNLVTNSdmNtRm5aUzVVZVhCbFBVOVRVenNLVDFOVExrRmpZMlZ6YzB0bGVWTmxZM0psZEQxbVNsQnJUSEp3WkUxU1NVVkNOa0o0WkhkaWNFUXhlRXB6YVhaRE9XZzdDazlUVXk1QlkyTmxjM05MWlhsSlJEMU1WRUZKTkVjMldubHBjVUprY2xrNVNFRXhUbkEyVkc4N0NrOVRVeTVDZFdOclpYUk9ZVzFsUFc1bGRXUmxkbWxqWlRzS1QxTlRMa1Z1WkZCdmFXNTBQV2gwZEhCek9pOHZiM056TFdOdUxYTm9ZVzVuYUdGcExtRnNhWGwxYm1OekxtTnZiVHNLUmxSUUxrSjFZMnRsZEU1aGJXVTlablJ3Y205dmREc0tURzluTGt4bGRtVnNQVmM3Q2cuLg..
//        encBase64 = AesUtil.encBase64(encBase64);
//        System.out.println("base641: "+encBase64);
        System.err.println("========================================================================");
        String plain_ = AesUtil.decrypt(enc);
        System.out.println("decode: "+plain_);
        System.err.println("========================================================================");

        String decBase64 = AesUtil.decBase64(encBase64);
        System.out.println("decBase640: "+decBase64);
        System.err.println("========================================================================");
//        decBase64 = AesUtil.decBase64(decBase64);
//        System.out.println("decBase641: "+decBase64);

        plain = decBase64;
        tv.setText(test(plain));
    }

    private String test(String src){
        String enc = AesUtil.encrypt(src);
        String dec = AesUtil.decrypt(enc);

        System.out.println("Enc: "+enc);
        System.out.println("Dec: "+dec);
        return dec;
    }
}
