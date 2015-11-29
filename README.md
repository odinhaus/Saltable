##USAGE
```C#
byte[] apk, ask, bpk, bsk;
// Gets Alice's keys
NaClClient.CreateKeys(out apk, out ask);
// Gets Bob's keys
NaClClient.CreateKeys(out bpk, out bsk);

// Alice's encryptor for Bob
var clientA = NaClClient.Create(apk, ask, bpk);
// Bob's encryptor for Alice
var clientB = NaClClient.Create(bpk, bsk, apk);

// get your plaintext bytes
byte[] clear = new byte[] { 1, 2, 3, 4, 5 };
byte[] nonce;

// Alice encrypts for Bob
byte[] cipher = clientA.Encrypt(e.Buffer, 0, e.BytesRecorded, out nonce);
// Bob decrypts from Alice
clear = clientB.Decrypt(cipher, nonce);
```
