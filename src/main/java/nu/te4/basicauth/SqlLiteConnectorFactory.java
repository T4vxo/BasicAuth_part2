/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nu.te4.basicauth;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 *
 * @author Daniel
 */
public class SqlLiteConnectorFactory {

    public static Connection getConnection() throws SQLException, ClassNotFoundException {
        Class.forName("org.sqlite.JDBC");
        Connection connection = DriverManager.getConnection("jdbc:sqlite:SQLiteTest1.db");
        Statement statement = connection.createStatement();
        ResultSet data = statement.executeQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='user'");
        if (!data.next()) {
            System.out.println("Building table");
            statement.execute("CREATE TABLE user(username varchar(100), password varchar(100), primary key(username))");
        }
        statement.close();
        return connection;
    }
}
