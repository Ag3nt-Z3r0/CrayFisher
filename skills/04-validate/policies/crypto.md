```xml
<policy type="crypto">

  <reportable>
    <condition id="gcm-no-auth-tag">
      AES-GCM decryption skips authTag verification, or setAuthTag is
      never called.
      Verify: read the code where decipher.final() is invoked without a
      preceding decipher.setAuthTag() call.
    </condition>
    <condition id="weak-cipher-sensitive-data">
      DES, RC4, ECB mode, or MD5/SHA1 (for signing/authentication purposes)
      is used on sensitive data.
      Verify: read the algorithm string ('des-ecb', 'rc4', 'md5', etc.)
      in the code and confirm the data being processed is sensitive
      (passwords, session tokens, payment information, etc.).
    </condition>
    <condition id="hardcoded-key-iv">
      An encryption key or IV is hardcoded in the source.
      Verify: read the arguments to createCipher or createDecipheriv.
    </condition>
    <condition id="static-iv">
      The IV (initialization vector) is always a fixed constant value.
      Verify: read the IV-generation code and confirm it is a constant
      without randomBytes.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="non-security-hash" reason="not a security purpose">
      MD5/SHA1 is used for non-security purposes such as cache keys,
      duplicate detection, or file-integrity checking.
      Verify: read the code to confirm how the hash result is used.
      If it is not used for authentication or signing, it is not a
      security weakness.
    </condition>
    <condition id="password-hashing-bcrypt" reason="intended design">
      Passwords are hashed with bcrypt, argon2, PBKDF2, or scrypt.
      This is correct design, not a vulnerability.
    </condition>
    <condition id="no-sensitive-data" reason="bounded impact">
      A weak algorithm is used, but the data being encrypted is non-sensitive
      public data.
      Verify: read the code to confirm what data is being encrypted.
    </condition>
    <condition id="deprecated-but-unused-path" reason="dead code">
      The weak algorithm exists, but the code path is never actually
      executed.
      Verify: confirm with grep that there are no callers.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you read the algorithm name string directly from the code?</item>
    <item>Did you confirm in the code whether the data being encrypted/decrypted is sensitive?</item>
    <item>For GCM, did you read the code to check whether setAuthTag is called?</item>
    <item>Did you read the key/IV generation code to confirm whether it is randomly generated or hardcoded?</item>
  </verify>

</policy>
```
