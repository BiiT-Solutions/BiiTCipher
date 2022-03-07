package com.biit.cipher;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

@SpringBootApplication
@ComponentScan({"com.biit.cipher"})
@PropertySource("classpath:application.properties")
@Service
public class TestEncryptorManagerServer {

    public static void main(String[] args) {
        SpringApplication.run(TestEncryptorManagerServer.class, args);
    }

}
