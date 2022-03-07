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
