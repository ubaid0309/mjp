// ByteMart reporting service - DEMO DATA, intentionally vulnerable. Do not deploy.
package com.bytemart.reports;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.crypto.Cipher;

public class ReportService {
    private final Connection connection;

    public ReportService(Connection connection) {
        this.connection = connection;
    }

    public ResultSet salesForRegion(String region) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM sales WHERE region = '" + region + "'");
    }

    public byte[] checksum(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DES");
    }

    public void archive(String month) throws Exception {
        Runtime.getRuntime().exec("zip -r /backups/" + month + ".zip /data/" + month);
    }
}
