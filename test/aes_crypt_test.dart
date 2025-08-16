import 'dart:math';
import 'dart:typed_data';

import 'package:aes_crypt_null_safe/aes_crypt_null_safe.dart';
import 'package:test/test.dart';
import 'package:universal_io/io.dart';

void main() {
  var random = Random();

  group('Algorithms', () {
    AesCrypt crypt = AesCrypt();
    Uint8List iv = Uint8List.fromList(
      List<int>.generate(16, (i) => random.nextInt(256)),
    );
    Uint8List key = Uint8List.fromList(
      List<int>.generate(32, (i) => random.nextInt(256)),
    );
    crypt.aesSetKeys(key, iv);
    int srcDataLen = 100016;
    Uint8List srcData = Uint8List.fromList(
      List<int>.generate(srcDataLen, (i) => random.nextInt(256)),
    );

    test('Test AES CBC encryption/decryption', () {
      crypt.aesSetMode(AesMode.cbc);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
    });

    test('Test AES ECB encryption/decryption', () {
      crypt.aesSetMode(AesMode.ecb);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
    });

    test('Test AES CFB encryption/decryption', () {
      crypt.aesSetMode(AesMode.cfb);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
    });

    test('Test AES OFB encryption/decryption', () {
      crypt.aesSetMode(AesMode.ofb);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
    });
  });

  AesCrypt crypt = AesCrypt();
  crypt.setPassword('passw 密碼 パスワード пароль كلمة السر ꜩꝕ 𐌰𐍉 𝕬𝖃');
  crypt.setOverwriteMode(AesCryptOwMode.warn);

  int srcDataLen = 100003;
  Uint8List srcData = Uint8List.fromList(
    List<int>.generate(srcDataLen, (i) => random.nextInt(256)),
  );

  group('Encryption/decryption', () {
    test('Test `encryptFileSync()` and `decryptFileSync()` functions', () {
      String srcFilepath = './test/testfile.txt';
      String encFilepath = './test/testfile2.txt.aes';
      String sourceData1 = File(srcFilepath).readAsStringSync();
      encFilepath = crypt.encryptFileSync(srcFilepath, encFilepath);
      String decFilepath = crypt.decryptFileSync(encFilepath);
      File(encFilepath).deleteSync();
      String sourceData2 = File(decFilepath).readAsStringSync();
      File(decFilepath).deleteSync();
      expect(sourceData2, equals(sourceData1));
    });

    test('Test `encryptFile()` and `decryptFile()` functions', () async {
      String srcFilepath = './test/testfile.txt';
      String encFilepath = './test/testfile2.txt.aes';
      String sourceData1 = await File(srcFilepath).readAsString();
      encFilepath = await crypt.encryptFile(srcFilepath, encFilepath);
      String decFilepath = await crypt.decryptFile(encFilepath);
      await File(encFilepath).delete();
      String sourceData2 = await File(decFilepath).readAsString();
      await File(decFilepath).delete();
      expect(sourceData2, equals(sourceData1));
    });

    test(
      'Test `decryptFileSync()` functions on a file encypted by AES Crypt software',
      () {
        String srcFilepath = './test/testfile.txt';
        String encFilepath = './test/testfile.txt.aes';
        String decFilepath = './test/testfile2.txt';
        String sourceData1 = File(srcFilepath).readAsStringSync();
        decFilepath = crypt.decryptFileSync(encFilepath, decFilepath);
        String sourceData2 = File(decFilepath).readAsStringSync();
        File(decFilepath).deleteSync();
        expect(sourceData2, equals(sourceData1));
      },
    );

    String encFilepath = './test/testfile2.txt.aes';

    test(
      'Test `encryptDataToFileSync()` and `decryptDataFromFileSync()` functions',
      () {
        encFilepath = crypt.encryptDataToFileSync(srcData, encFilepath);
        Uint8List decryptedData = crypt.decryptDataFromFileSync(encFilepath);
        File(encFilepath).deleteSync();
        expect(srcData.isEqual(decryptedData), equals(true));
      },
    );

    test(
      'Test `encryptDataToFile()` and `decryptDataFromFile()` functions',
      () async {
        encFilepath = await crypt.encryptDataToFile(srcData, encFilepath);
        Uint8List decryptedData = await crypt.decryptDataFromFile(encFilepath);
        await File(encFilepath).delete();
        expect(srcData.isEqual(decryptedData), equals(true));
      },
    );

    String decString;
    String srcString =
        'hglakj 密碼 パスワード фбмгцз كلمة السر ꜩꝕ 𐌰𐍉 𝕬𝖃 aalkjhflaeiuwoefdnscvsmnskdjfhoweqirhowqefasdnl';

    test('Encrypt/decrypt UTF8 string <=> file', () {
      crypt.encryptTextToFileSync(srcString, encFilepath); // bom = false
      decString = crypt.decryptTextFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF8 string with BOM <=> file', () {
      crypt.encryptTextToFileSync(
        srcString,
        encFilepath,
        bom: true,
      ); // bom = true
      decString = crypt.decryptTextFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF16 BE string <=> file', () {
      crypt.encryptTextToFileSync(
        srcString,
        encFilepath,
        utf16: true,
      ); // bom = false, endian = Endian.big
      decString = crypt.decryptTextFromFileSync(encFilepath, utf16: true);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF16 BE string with BOM <=> file', () {
      crypt.encryptTextToFileSync(
        srcString,
        encFilepath,
        utf16: true,
        bom: true,
      ); // bom = true, endian = Endian.big
      decString = crypt.decryptTextFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF16 LE string <=> file', () {
      crypt.encryptTextToFileSync(
        srcString,
        encFilepath,
        utf16: true,
        endian: Endian.little,
      ); // bom = false, endian = Endian.little
      decString = crypt.decryptTextFromFileSync(
        encFilepath,
        utf16: true,
        endian: Endian.little,
      );
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF16 LE string with BOM <=> file', () {
      crypt.encryptTextToFileSync(
        srcString,
        encFilepath,
        utf16: true,
        endian: Endian.little,
        bom: true,
      ); // bom = true, endian = Endian.little
      decString = crypt.decryptTextFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });
  });
}

extension _Uint8ListExtension on Uint8List {
  bool isEqual(Uint8List other) {
    if (identical(this, other)) return true;
    int length = this.length;
    if (length != other.length) return false;
    for (int i = 0; i < length; i++) {
      if (this[i] != other[i]) return false;
    }
    return true;
  }
}
