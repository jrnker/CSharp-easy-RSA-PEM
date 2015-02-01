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


            Console.WriteLine("*** Load key from file and encrypt test ***");
            Console.WriteLine("Loading premade private keys..");
            string loadedRSA = File.ReadAllText("keys\\private.rsa.pem"); 
            RSACryptoServiceProvider privateRSAkey = Crypto.DecodeRsaPrivateKey(loadedRSA); 

            Console.WriteLine("Loading premade public key..");
            string loadedX509 = File.ReadAllText("keys\\public.x509.pem"); 
            RSACryptoServiceProvider publicX509key = Crypto.DecodeX509PublicKey(loadedX509);

            string secret = "Hello world";
            Console.WriteLine("Using public key, encrypt \"" + secret + "\"..");
            string supersecret = Crypto.EncryptString(secret, publicX509key);
            Console.WriteLine("Encrypted: " + supersecret);

            Console.WriteLine("Using private key, decrypt..");
            string decodesecret = Crypto.DecryptString(supersecret, privateRSAkey);
            Console.WriteLine("Decrypted: " + decodesecret);
            
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();




            Console.WriteLine("\n*** Key export test ***");
            Console.WriteLine("Make new PEM keys based on the loaded keys.."); 

            string madeRSA = Crypto.ExportPrivateKeyToRSAPEM(privateRSAkey);     // <- This is what is commonly used as private key 
            string madeX509 = Crypto.ExportPublicKeyToX509PEM(publicX509key);     // <- This is what is commonly used as public key

            // Let's polish the variables for neatness and so that we can easily compare them.
            loadedRSA = loadedRSA.Replace("\r", "");
            loadedX509 = loadedX509.Replace("\r", "");

            Console.WriteLine("Loaded and made private keys are equal: " + (loadedRSA == madeRSA).ToString());
            Console.WriteLine("Loaded and made public are equal: " + (loadedX509 == madeX509).ToString());

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();




            Console.WriteLine("\n*** Public key manufacturing test ***");
            Console.WriteLine("Make a new public key from the private key..");

            string madeX509privateRSAkey = Crypto.ExportPublicKeyToX509PEM(privateRSAkey);
            Console.WriteLine("Public keys made from public and private are the equal: " + (madeX509privateRSAkey == madeX509).ToString());

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();

             

            Console.WriteLine("\n*** Key pair manufacturing test ***");
            Console.WriteLine("Make new key and save to disk..");

            RSACryptoServiceProvider newKey = Crypto.CreateRsaKeys();
            File.WriteAllText("keys\\newPrivate.pem", Crypto.ExportPrivateKeyToRSAPEM(privateRSAkey));
            File.WriteAllText("keys\\newPublic.pem", Crypto.ExportPublicKeyToX509PEM(privateRSAkey));

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();

        }
    }
}
