# For encrypt/decrypt data.

This project is only a cipher structure that can be used later for implementing different cipher algorithms. Includes common classes and properties that will be
used in any other cipher library from BiiT.

### Import the dependency

Include in your `pom.xml`

```
<dependency>
    <groupId>com.biit-solutions</groupId>
    <artifactId>cipher</artifactId>
    <version>${cipher.version}</version>
</dependency>
```

### Set the Spring Boot configuration

Use the next settings to customize your encryption. You can define the key and the salt value.

```
encryption.key=asd123
encryption.salt=123456
```

Also, if you want to change the pool size of ciphers to a value different from 10, you can set this property:

```
cipher.pool.size=15
```

Remember to include the package `com.biit.cipher` into the Spring configuration:

```
@ComponentScan({"com.biit.cipher", "..."})
```

# Logging information

You can enable the log of this library adding the next logger into your `logback.xml`

```
<logger name="com.biit.cipher.logger.CipherLogger" additivity="false" level="DEBUG">
    <appender-ref ref="DAILY"/>
    <appender-ref ref="CONSOLE"/>
</logger>
``` 