import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:aes_crypt/aes_crypt.dart';
import 'package:test/test.dart';

void main() {
  AESCrypt aes = AESCrypt();

  String passphrase = 'passw 密碼 パスワード пароль كلمة السر';

  group('A group of tests', () {
    test('Test `encryptFile` and `decryptFile` functions', () {
      String dec_filepath = './test/testfile1.txt';
      String source_data1 = File(dec_filepath).readAsStringSync();

      String enc_filepath = aes.encryptFileSync(passphrase, dec_filepath);
      dec_filepath = aes.decryptFileSync(passphrase, enc_filepath);
      File(enc_filepath).deleteSync();
      String source_data2 = File(dec_filepath).readAsStringSync();
      File(dec_filepath).deleteSync();
      expect(source_data2, equals(source_data1));
    });

    test('Test `encryptDataToFile` and `decryptDataFromFile` functions', () {
      String source_string =
          'Варкалось. Хливкие шорьки пырялись по наве, и хрюкотали зелюки, как '
          'мюмзики в мове. (Jabberwocky by Lewis Carroll, russian translation)';
      String enc_filepath = './test/testfile2.txt.aes';

      enc_filepath = aes.encryptDataToFileSync(
          passphrase, utf8.encode(source_string), enc_filepath);
      Uint8List decrypted_data =
          aes.decryptDataFromFileSync(passphrase, enc_filepath);
      File(enc_filepath).deleteSync();
      String decrypted_string = utf8.decode(decrypted_data);

      expect(decrypted_string, equals(source_string));
    });
  });
}