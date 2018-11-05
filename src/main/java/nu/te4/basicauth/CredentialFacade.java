/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nu.te4.basicauth;

import at.favre.lib.crypto.bcrypt.BCrypt;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 *
 * @author TE4-Lärardator
 */
public class CredentialFacade {

    public static Credentials createCredentials(String basicAuth) {
        //Basic ZGFuaWVsOm1lZ2FoZW1saWd0bPZzZW5vcmQ=
        basicAuth = basicAuth.substring(6).trim();
        //ZGFuaWVsOm1lZ2FoZW1saWd0bPZzZW5vcmQ=
        byte[] bytes = Base64.getDecoder().decode(basicAuth);
        //byte = [100,96,233,5,...]
        basicAuth = new String(bytes);
        //daniel:megahemligtlösenord
        int colon = basicAuth.indexOf(":");
        String username = basicAuth.substring(0, colon);
        String password = basicAuth.substring(colon + 1);
        return new Credentials(username, password);
    }

    public static void save(Credentials credentials) {
        //hasha lösenord
        String hashedpassword = BCrypt.withDefaults()
                .hashToString(12, credentials.getPassword().toCharArray());
        // spara i databas
        try (Connection connection = SqlLiteConnectorFactory.getConnection()) {
            Statement stmt = connection.createStatement();
            String sql = String.format("INSERT INTO user VALUES('%s','%s')",
                     credentials.getUsername(), hashedpassword);
            stmt.executeUpdate(sql);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public static Credentials get(String username) {
        try (Connection connection = SqlLiteConnectorFactory.getConnection()) {
            Statement stmt = connection.createStatement();
            String sql = String.format("SELECT * FROM user WHERE username='%s'", username);
            ResultSet data = stmt.executeQuery(sql);
            data.next();
            return new Credentials(data.getString("username"), data.getString("password"));
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return null;
        }
    }

    public static boolean verify(String username, String password) {
        Credentials credentials = get(username);
        //username + hashade lösenordet!
        BCrypt.Result result = BCrypt.verifyer()
                .verify(password.toCharArray(), credentials.getPassword());
        //klartext             hashat från databasen
        return result.verified;
    }

    public static List<Credentials> getAllUsers() {
        List<Credentials> users = new ArrayList<>();
        try (Connection connection = SqlLiteConnectorFactory.getConnection()) {
            Statement stmt = connection.createStatement();
            String sql = "SELECT * FROM user";
            ResultSet data = stmt.executeQuery(sql);
            while (data.next()) {
                String username = data.getString("username");
                String password = data.getString("password");
                Credentials cred = new Credentials(username, password);
                users.add(cred);
            }
            return users;
        } catch (Exception e) {
            return null;
        }
    }
}
