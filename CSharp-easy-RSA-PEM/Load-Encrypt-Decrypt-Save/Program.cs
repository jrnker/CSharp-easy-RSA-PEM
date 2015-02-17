using CSharp_easy_RSA_PEM;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Load_Encrypt_Decrypt_Save
{
    class Program
    {
        static void Main(string[] args)
        {
            // Private keys as PKCS#1, this is the most common way to store the private keys. Also just known as RSA keys.
            // Public keys as X.509, this is the most common way to store the public keys.

            DateTime t1; //To use for timings

            #region Load key from file and encrypt test
            t1 = DateTime.Now;
            Console.WriteLine("*** Load key from file and encrypt test ***");
            Console.WriteLine("Loading premade private keys..");
            string loadedRSA = File.ReadAllText("keys/private.rsa.pem");
            RSACryptoServiceProvider privateRSAkey = Crypto.DecodeRsaPrivateKey(loadedRSA);

            Console.WriteLine("Loading premade public key..");
            string loadedX509 = File.ReadAllText("keys/public.x509.pem");
            RSACryptoServiceProvider publicX509key = Crypto.DecodeX509PublicKey(loadedX509);

            string secret = "Hello world - 1";
            Console.WriteLine("Using public key, encrypt \"" + secret + "\"..");
            string supersecret = Crypto.EncryptString(secret, publicX509key);
            Console.WriteLine("Encrypted: " + supersecret);

            Console.WriteLine("Using private key, decrypt..");
            string decodesecret = Crypto.DecryptString(supersecret, privateRSAkey);
            Console.WriteLine("Decrypted: " + decodesecret);

            Console.WriteLine("Completed in " + (DateTime.Now - t1).TotalSeconds + "s");
            Console.WriteLine("\nPress any key to continue...");
            Console.Read();
            #endregion


            #region Key export test
            t1 = DateTime.Now;
            Console.WriteLine("\n*** Key export test ***");
            Console.WriteLine("Make new PEM keys based on the loaded keys..");

            string madeRSA = Crypto.ExportPrivateKeyToRSAPEM(privateRSAkey);     // <- This is what is commonly used as private key 
            string madeX509 = Crypto.ExportPublicKeyToX509PEM(publicX509key);     // <- This is what is commonly used as public key

            // Let's polish the variables for neatness and so that we can easily compare them.
            loadedRSA = loadedRSA.Replace("\r", "");
            loadedX509 = loadedX509.Replace("\r", "");

            Console.WriteLine("Loaded and made private keys are equal: " + (loadedRSA == madeRSA).ToString());
            Console.WriteLine("Loaded and made public are equal: " + (loadedX509 == madeX509).ToString());

            Console.WriteLine("Completed in " + (DateTime.Now - t1).TotalSeconds + "s");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
            #endregion


            #region Public key manufacturing test
            t1 = DateTime.Now;
            Console.WriteLine("\n*** Public key manufacturing test ***");
            Console.WriteLine("Make a new public key from the private key..");

            string madeX509privateRSAkey = Crypto.ExportPublicKeyToX509PEM(privateRSAkey);
            Console.WriteLine("Public keys made from public and private are the equal: " + (madeX509privateRSAkey == madeX509).ToString());

            Console.WriteLine("Completed in " + (DateTime.Now - t1).TotalSeconds + "s");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();

            t1 = DateTime.Now;
            Console.WriteLine("\n*** Key pair manufacturing test ***");
            Console.WriteLine("Make new key and save to disk..");

            RSACryptoServiceProvider newKey = Crypto.CreateRsaKeys();
            File.WriteAllText("keys\\newPrivate.pem", Crypto.ExportPrivateKeyToRSAPEM(privateRSAkey));
            File.WriteAllText("keys\\newPublic.pem", Crypto.ExportPublicKeyToX509PEM(privateRSAkey));

            Console.WriteLine("Completed in " + (DateTime.Now - t1).TotalSeconds + "s");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
            #endregion


            #region Private key signing and public key verifying test - signing hashed message SHA1
            t1 = DateTime.Now;
            Console.WriteLine("\n*** Private key signing and public key verifying test - signing hashed message SHA1 ***");

            SHA1Managed sha1 = new SHA1Managed();
            string importantMessage = "Hello world - 2";
            byte[] importantMessageBytes = Encoding.UTF8.GetBytes(importantMessage);
            byte[] hashedMessage = sha1.ComputeHash(importantMessageBytes);

            Console.WriteLine("Sign this message with the private key: " + importantMessage);
            Console.WriteLine("and verify that the signature is okay with the public key.");

            byte[] bytes = privateRSAkey.SignHash(hashedMessage, CryptoConfig.MapNameToOID("SHA1"));
            string signature = Convert.ToBase64String(bytes);

            Console.WriteLine("Signature: " + signature);


            byte[] signatureBytes = Convert.FromBase64String(signature);
            bool isSignatureOkay = publicX509key.VerifyHash(hashedMessage, CryptoConfig.MapNameToOID("SHA1"), signatureBytes);

            Console.WriteLine("Signature is okay: " + isSignatureOkay);

            Console.WriteLine("Completed in " + (DateTime.Now - t1).TotalSeconds + "s");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
            #endregion


            #region Private key signing and public key verifying test - signing hashed message SHA256
            t1 = DateTime.Now;
            Console.WriteLine("\n*** Private key signing and public key verifying test - signing hashed message SHA256 ***");

            SHA256Managed sha256 = new SHA256Managed();
            importantMessage = "Hello world - 4";
            importantMessageBytes = Encoding.UTF8.GetBytes(importantMessage);
            hashedMessage = sha256.ComputeHash(importantMessageBytes);

            Console.WriteLine("Sign this message with the private key: " + importantMessage);
            Console.WriteLine("and verify that the signature is okay with the public key.");

            bytes = privateRSAkey.SignHash(hashedMessage, CryptoConfig.MapNameToOID("SHA256"));
            signature = Convert.ToBase64String(bytes);

            Console.WriteLine("Signature: " + signature);


            signatureBytes = Convert.FromBase64String(signature);
            isSignatureOkay = publicX509key.VerifyHash(hashedMessage, CryptoConfig.MapNameToOID("SHA256"), signatureBytes);

            Console.WriteLine("Signature is okay: " + isSignatureOkay);

            Console.WriteLine("Completed in " + (DateTime.Now - t1).TotalSeconds + "s");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
            #endregion


            #region Private key signing and public key verifying test - signing full message SHA256
            t1 = DateTime.Now;
            Console.WriteLine("\n*** Private key signing and public key verifying test - signing full message SHA256 ***");

            importantMessage = "Hello world - 3";
            importantMessageBytes = Encoding.UTF8.GetBytes(importantMessage);
            Console.WriteLine("Sign this message with the private key: " + importantMessage);
            Console.WriteLine("and verify that the signature is okay with the public key.");

            bytes = privateRSAkey.SignData(importantMessageBytes, typeof(SHA256));
            signature = Convert.ToBase64String(bytes);

            Console.WriteLine("Signature: " + signature);


            signatureBytes = Convert.FromBase64String(signature);
            isSignatureOkay = publicX509key.VerifyData(importantMessageBytes, typeof(SHA256), signatureBytes);

            Console.WriteLine("Signature is okay: " + isSignatureOkay);

            Console.WriteLine("Completed in " + (DateTime.Now - t1).TotalSeconds + "s");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
            #endregion

        }
    }
}
