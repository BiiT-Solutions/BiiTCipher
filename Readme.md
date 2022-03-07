# For encrypt/decrypt data.

### Import the dependency

Include in your `pom.xml`

```
<dependency>
    <groupId>com.biit</groupId>
    <artifactId>cipher</artifactId>
    <version>${cipher.version}</version>
</dependency>
```

### Set the Spring Boot configuration

Use the next settings to customize your encryption.

```
encryption.key=asd123
encryption.salt=123456
```

# Logging information
You can enable the log of this library adding the next logger into your `logback.xml`

```
<logger name="com.biit.cipher.logger.CipherLogger" additivity="false" level="DEBUG">
    <appender-ref ref="DAILY"/>
    <appender-ref ref="CONSOLE"/>
</logger>
``