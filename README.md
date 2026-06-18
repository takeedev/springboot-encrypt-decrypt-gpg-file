# springboot-encrypt-decrypt-gpg-file

Spring Boot project สำหรับทดลองเข้ารหัสและถอดรหัสไฟล์ด้วย OpenPGP/GPG โดยใช้ Bouncy Castle

## Project Summary

โปรเจกต์นี้เป็นตัวอย่างการทำงานกับไฟล์ PGP ใน Java:

- โหลด public key จากไฟล์ `.asc`
- เข้ารหัสไฟล์ด้วย public key และ AES-256
- โหลด private key จากไฟล์ `.asc` พร้อม passphrase
- ถอดรหัสไฟล์ `.pgp` กลับเป็นไฟล์ plaintext

โค้ดหลักอยู่ใน package `takee.dev.gpg`:

- `GpgApplication.java` - Spring Boot entry point
- `KeyService.java` - โหลด public/private key จาก input stream
- `EncryptionService.java` - เข้ารหัสข้อมูลด้วย `PGPEncryptedDataGenerator`
- `DecryptionService.java` - ถอดรหัสข้อมูลด้วย `PGPPublicKeyEncryptedData`
- `GpgApplicationTests.java` - integration test ที่ encrypt `src/test/java/resource/example.txt` เป็น `example.txt.pgp` และ decrypt กลับเป็น `test.txt`

## Tech Stack

- Java 25
- Spring Boot `4.1.0-SNAPSHOT`
- Maven
- Bouncy Castle `bcprov-jdk18on` และ `bcpg-jdk18on` เวอร์ชัน `1.83`
- Lombok

## Project Structure

```text
src/main/java/takee/dev/gpg/
  GpgApplication.java
  config/
    BouncyCastleConfig.java
  service/
    KeyService.java
    EncryptionService.java
    DecryptionService.java

src/main/resources/
  application.yaml
  keys/
    public_key.asc
    private_key.asc
    passphrase.txt

src/test/java/takee/dev/gpg/
  GpgApplicationTests.java

src/test/java/resource/
  example.txt
```

## How It Works

1. `KeyService.loadPublicKey(...)` อ่าน public key จาก armored key file
2. `EncryptionService.encrypt(...)` ใช้ public key เข้ารหัส input stream แล้วเขียนออก output stream
3. `KeyService.loadPrivateKey(...)` อ่าน secret key และถอด private key ด้วย passphrase
4. `DecryptionService.decrypt(...)` ใช้ private key ถอดรหัสไฟล์ encrypted แล้วเขียน plaintext ออก output stream

## Run Tests

```command
./mvnw test
```

ผลลัพธ์จาก test จะสร้างไฟล์:

- `example.txt.pgp`
- `test.txt`

## GPG Commands

Create key:

```command
gpg --full-generate-key
```

List keys:

```command
gpg --list-keys
```

Export public key:

```command
gpg --armor --output public_key.asc --export "{e-mail}"
```

Import public key:

```command
gpg --import public_key.asc
```

Export private key:

```command
gpg --armor --output private_key.asc --export-secret-keys "{e-mail}"
```

Encrypt a file with GPG:

```command
gpg --encrypt --recipient "{e-mail}" filename.txt
```

Decrypt a file with GPG:

```command
gpg --output filename.txt --decrypt filename.txt.pgp
```