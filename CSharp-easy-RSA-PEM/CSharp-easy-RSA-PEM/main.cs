using CSInteropKeys;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CSharp_easy_RSA_PEM
{
    public class Crypto
    {
        /// <summary>
        /// This helper function parses an RSA private key using the ASN.1 format
        /// </summary>
        /// <param name="privateKeyBytes">Byte array containing PEM string of private key.</param>
        /// <returns>An instance of <see cref="RSACryptoServiceProvider"/> rapresenting the requested private key.
        /// Null if method fails on retriving the key.</returns>
        public static RSACryptoServiceProvider DecodeRsaPrivateKey(string privateKey,string password="")
        {
            Dictionary<string, string> extras = new Dictionary<string, string>();
            byte[] bytes = Helpers.GetBytesFromPEM(privateKey, out extras);

            if (extras.Any(x => x.Value.Contains("ENCRYPTED")) && extras.Any(x => x.Key.Contains("DEK-Inf")))
            {
                String saltstr = extras.First(x => x.Key.Contains("DEK-Inf")).Value.Split(',')[1].Trim();
                byte[] salt = new byte[saltstr.Length / 2];

                for (int i = 0; i < salt.Length; i++)
                    salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
                SecureString despswd = new SecureString(); // GetSecPswd("Enter password to derive 3DES key==>");
                foreach (char c in password)
                    despswd.AppendChar(c);
                byte[] decoded = DecryptRSAPrivatePEM(bytes, salt, despswd);
                bytes = decoded;
            }

            return DecodeRsaPrivateKey(bytes);
        }
        public static RSACryptoServiceProvider DecodeRsaPrivateKey(byte[] privateKeyBytes)// PKCS1 
        {
            MemoryStream ms = new MemoryStream(privateKeyBytes);
            BinaryReader rd = new BinaryReader(ms);

            try
            {
                byte byteValue;
                ushort shortValue;

                shortValue = rd.ReadUInt16();

                switch (shortValue)
                {
                    case 0x8130:
                        // If true, data is little endian since the proper logical seq is 0x30 0x81
                        rd.ReadByte(); //advance 1 byte
                        break;
                    case 0x8230:
                        rd.ReadInt16();  //advance 2 bytes
                        break;
                    default:
                        Debug.Assert(false);     // Improper ASN.1 format
                        return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue != 0x0102) // (version number)
                {
                    Debug.Assert(false);     // Improper ASN.1 format, unexpected version number
                    return null;
                }

                byteValue = rd.ReadByte();
                if (byteValue != 0x00)
                {
                    Debug.Assert(false);     // Improper ASN.1 format
                    return null;
                }

                // The data following the version will be the ASN.1 data itself, which in our case
                // are a sequence of integers.

                // In order to solve a problem with instancing RSACryptoServiceProvider
                // via default constructor on .net 4.0 this is a hack
                CspParameters parms = new CspParameters();
                parms.Flags = CspProviderFlags.NoFlags;
                parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);
                RSAParameters rsAparams = new RSAParameters();

                rsAparams.Modulus = rd.ReadBytes(Helpers.DecodeIntegerSize(rd));

                // Argh, this is a pain.  From emperical testing it appears to be that RSAParameters doesn't like byte buffers that
                // have their leading zeros removed.  The RFC doesn't address this area that I can see, so it's hard to say that this
                // is a bug, but it sure would be helpful if it allowed that. So, there's some extra code here that knows what the
                // sizes of the various components are supposed to be.  Using these sizes we can ensure the buffer sizes are exactly
                // what the RSAParameters expect.  Thanks, Microsoft.
                RSAParameterTraits traits = new RSAParameterTraits(rsAparams.Modulus.Length * 8);

                rsAparams.Modulus = Helpers.AlignBytes(rsAparams.Modulus, traits.size_Mod);
                rsAparams.Exponent = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Exp);
                rsAparams.D = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_D);
                rsAparams.P = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_P);
                rsAparams.Q = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Q);
                rsAparams.DP = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DP);
                rsAparams.DQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DQ);
                rsAparams.InverseQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_InvQ);

                rsa.ImportParameters(rsAparams);
                return rsa;
            }
            catch (Exception e)
            {
                Debug.Assert(false);
                return null;
            }
            finally
            {
                rd.Close();
            }
        }
        public static RSACryptoServiceProvider DecodeRsaPublicKey(string publicKey)
        {
            return DecodeRsaPublicKey(Helpers.GetBytesFromPEM(publicKey));
        }
        public static RSACryptoServiceProvider DecodeRsaPublicKey(byte[] publicKeyBytes)   // PKCS1
        {
            MemoryStream ms = new MemoryStream(publicKeyBytes);
            BinaryReader rd = new BinaryReader(ms);
            try
            {
                byte byteValue;
                ushort shortValue;

                shortValue = rd.ReadUInt16();

                switch (shortValue)
                {
                    case 0x8130:
                        // If true, data is little endian since the proper logical seq is 0x30 0x81
                        rd.ReadByte(); //advance 1 byte
                        break;
                    case 0x8230:
                        rd.ReadInt16();  //advance 2 bytes
                        break;
                    default:
                        Debug.Assert(false);     // Improper ASN.1 format
                        return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue != 0x0102) // (version number)
                {
                    Debug.Assert(false);     // Improper ASN.1 format, unexpected version number
                    return null;
                }

                byteValue = rd.ReadByte();
                if (byteValue != 0x00)
                {
                    Debug.Assert(false);     // Improper ASN.1 format
                    return null;
                }

                // The data following the version will be the ASN.1 data itself, which in our case
                // are a sequence of integers.

                // In order to solve a problem with instancing RSACryptoServiceProvider
                // via default constructor on .net 4.0 this is a hack
                CspParameters parms = new CspParameters();
                parms.Flags = CspProviderFlags.NoFlags;
                parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);
                RSAParameters rsAparams = new RSAParameters();

                rsAparams.Modulus = rd.ReadBytes(Helpers.DecodeIntegerSize(rd));

                // Argh, this is a pain.  From emperical testing it appears to be that RSAParameters doesn't like byte buffers that
                // have their leading zeros removed.  The RFC doesn't address this area that I can see, so it's hard to say that this
                // is a bug, but it sure would be helpful if it allowed that. So, there's some extra code here that knows what the
                // sizes of the various components are supposed to be.  Using these sizes we can ensure the buffer sizes are exactly
                // what the RSAParameters expect.  Thanks, Microsoft.
                RSAParameterTraits traits = new RSAParameterTraits(rsAparams.Modulus.Length * 8);

                rsAparams.Modulus = Helpers.AlignBytes(rsAparams.Modulus, traits.size_Mod);
                rsAparams.Exponent = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Exp);
                //rsAparams.D = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_D);
                //rsAparams.P = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_P);
                //rsAparams.Q = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Q);
                //rsAparams.DP = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DP);
                //rsAparams.DQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DQ);
                //rsAparams.InverseQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_InvQ);

                rsa.ImportParameters(rsAparams);
                return rsa;
            }
            catch (Exception e)
            {
                Debug.Assert(false);
                return null;
            }
            finally
            {
                rd.Close();
            }
        }
        public static RSACryptoServiceProvider DecodeX509PublicKey(string publicKey)
        {
            return DecodePublicKey(Helpers.GetBytesFromPEM(publicKey));
        }
        public static RSACryptoServiceProvider DecodePublicKey(byte[] publicKeyBytes)       // x509
        {
            MemoryStream ms = new MemoryStream(publicKeyBytes);
            BinaryReader rd = new BinaryReader(ms);
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            try
            {
                byte byteValue;
                ushort shortValue;

                shortValue = rd.ReadUInt16();

                switch (shortValue)
                {
                    case 0x8130:
                        // If true, data is little endian since the proper logical seq is 0x30 0x81
                        rd.ReadByte(); //advance 1 byte
                        break;
                    case 0x8230:
                        rd.ReadInt16();  //advance 2 bytes
                        break;
                    default:
                        Debug.Assert(false);     // Improper ASN.1 format
                        return null;
                }

                seq = rd.ReadBytes(15);		//read the Sequence OID
                if (!Helpers.CompareBytearrays(seq, SeqOID))	//make sure Sequence for OID is correct
                    return null;

                shortValue = rd.ReadUInt16();
                if (shortValue == 0x8103)	//data read as little endian order (actual data order for Bit String is 03 81)
                    rd.ReadByte();	//advance 1 byte
                else if (shortValue == 0x8203)
                    rd.ReadInt16();	//advance 2 bytes
                else
                    return null;

                byteValue = rd.ReadByte();
                if (byteValue != 0x00)
                {
                    Debug.Assert(false);     // Improper ASN.1 format
                    return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                    rd.ReadByte();	//advance 1 byte
                else if (shortValue == 0x8230)
                    rd.ReadInt16();	//advance 2 bytes
                else
                    return null;

                // The data following the version will be the ASN.1 data itself, which in our case
                // are a sequence of integers.

                // In order to solve a problem with instancing RSACryptoServiceProvider
                // via default constructor on .net 4.0 this is a hack
                CspParameters parms = new CspParameters();
                parms.Flags = CspProviderFlags.NoFlags;
                parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);
                RSAParameters rsAparams = new RSAParameters();

                rsAparams.Modulus = rd.ReadBytes(Helpers.DecodeIntegerSize(rd));

                // Argh, this is a pain.  From emperical testing it appears to be that RSAParameters doesn't like byte buffers that
                // have their leading zeros removed.  The RFC doesn't address this area that I can see, so it's hard to say that this
                // is a bug, but it sure would be helpful if it allowed that. So, there's some extra code here that knows what the
                // sizes of the various components are supposed to be.  Using these sizes we can ensure the buffer sizes are exactly
                // what the RSAParameters expect.  Thanks, Microsoft.
                RSAParameterTraits traits = new RSAParameterTraits(rsAparams.Modulus.Length * 8);

                rsAparams.Modulus = Helpers.AlignBytes(rsAparams.Modulus, traits.size_Mod);
                rsAparams.Exponent = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Exp);
                //rsAparams.D = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_D);
                //rsAparams.P = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_P);
                //rsAparams.Q = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Q);
                //rsAparams.DP = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DP);
                //rsAparams.DQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_DQ);
                //rsAparams.InverseQ = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_InvQ);

                rsa.ImportParameters(rsAparams);
                return rsa;
            }
            catch (Exception e)
            {
                Debug.Assert(false);
                return null;
            }
            finally
            {
                rd.Close();
            }
        }

        public static string ExportPrivateKeyToRSAPEM(RSACryptoServiceProvider csp) // PKCS1
        {
            TextWriter outputStream = new StringWriter();

            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    Helpers.EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.D);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.P);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    Helpers.EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return packagePEM(stream.GetBuffer(), PEMtypes.PEM_RSA);
                //var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                //outputStream.WriteLine(Helpers.PEMheader(PEMtypes.PEM_RSA));//  "-----BEGIN RSA PRIVATE KEY-----");
                //// Output as Base64 with lines chopped at 64 characters
                //for (var i = 0; i < base64.Length; i += 64)
                //{
                //    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                //}
                //outputStream.WriteLine(Helpers.PEMfooter(PEMtypes.PEM_RSA)); //"-----END RSA PRIVATE KEY-----");
            }
            //return outputStream.ToString().Replace("\r","").Replace("\n\n", "\n");
        }
        public static String ExportPublicKeyToRSAPEM(RSACryptoServiceProvider csp)   // PKCS1
        {
            TextWriter outputStream = new StringWriter();

            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    Helpers.EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent);

                    //All Parameter Must Have Value so Set Other Parameter Value Whit Invalid Data  (for keeping Key Structure  use "parameters.Exponent" value for invalid data)
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.D
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.P
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.Q
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.DP
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.DQ
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.InverseQ

                    var length = (int)innerStream.Length;
                    Helpers.EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return packagePEM(stream.GetBuffer(), PEMtypes.PEM_RSA_PUBLIC);

                //var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                //outputStream.WriteLine(Helpers.PEMheader(PEMtypes.PEM_RSA_PUBLIC));
                //// Output as Base64 with lines chopped at 64 characters
                //for (var i = 0; i < base64.Length; i += 64)
                //{
                //    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                //}
                //outputStream.WriteLine(Helpers.PEMfooter(PEMtypes.PEM_RSA_PUBLIC));

                //return outputStream.ToString();

            }
        }
        public static String ExportPrivateKeyToPKCS8PEM(RSACryptoServiceProvider csp)   // PKCS8
        {
            // Encoded key
            AsnKeyBuilder.AsnMessage key = null;
            // actualKey
            RSAParameters actualKey = csp.ExportParameters(true);
            key = AsnKeyBuilder.PrivateKeyToPKCS8(actualKey);

            return packagePEM(key.GetBytes(), PEMtypes.PEM_RSA);

        }
        public static String ExportPublicKeyToX509PEM(RSACryptoServiceProvider csp)   // x509
        {
            // Encoded key
            AsnKeyBuilder.AsnMessage key = null;
            // actualKey
            RSAParameters actualKey = csp.ExportParameters(false);
            key = AsnKeyBuilder.PublicKeyToX509(actualKey);

            return packagePEM(key.GetBytes(), PEMtypes.PEM_PUBLIC);

        }
        public static string packagePEM(byte[] bytes,PEMtypes type)
        {
            TextWriter outputStream = new StringWriter();
            outputStream.NewLine = "\n";

            var base64 = Convert.ToBase64String(bytes, 0, (int)bytes.Length).ToCharArray();
            outputStream.WriteLine(Helpers.PEMheader(type)); 

            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
            }
            outputStream.WriteLine(Helpers.PEMfooter(type));
            return outputStream.ToString();

        }

        public static byte[] DecryptRSAPrivatePEM(byte[] privateKey, byte[] salt, SecureString despswd)
        {

            //------ Get the 3DES 24 byte key using PDK used by OpenSSL ----

            //SecureString despswd = new SecureString(); // GetSecPswd("Enter password to derive 3DES key==>");
            //foreach (char c in "password")
            //    despswd.AppendChar(c);

            //Console.Write("\nEnter password to derive 3DES key: ");
            //String pswd = Console.ReadLine();
            byte[] deskey = GetOpenSSL3deskey(salt, despswd, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
            if (deskey == null)
                return null;
            //showBytes("3DES key", deskey) ;

            //------ Decrypt the encrypted 3des-encrypted RSA private key ------
            byte[] rsakey = DecryptKey(privateKey, deskey, salt);	//OpenSSL uses salt value in PEM header also as 3DES IV
            if (rsakey != null)
                return rsakey;	//we have a decrypted RSA private key
            else
            {
                Console.WriteLine("Failed to decrypt RSA private key; probably wrong password.");
                return null;
            }
        }
        // ----- Decrypt the 3DES encrypted RSA private key ---------- 
        public static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV)
        {
            MemoryStream memst = new MemoryStream();
            TripleDES alg = TripleDES.Create();
            alg.Key = desKey;
            alg.IV = IV;
            try
            {
                CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write);
                cs.Write(cipherData, 0, cipherData.Length);
                cs.Close();
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                return null;
            }
            byte[] decryptedData = memst.ToArray();
            return decryptedData;
        }
        //-----   OpenSSL PBKD uses only one hash cycle (count); miter is number of iterations required to build sufficient bytes ---
        private static byte[] GetOpenSSL3deskey(byte[] salt, SecureString secpswd, int count, int miter)
        {
            IntPtr unmanagedPswd = IntPtr.Zero;
            int HASHLENGTH = 16;	//MD5 bytes
            byte[] keymaterial = new byte[HASHLENGTH * miter];     //to store contatenated Mi hashed results


            byte[] psbytes = new byte[secpswd.Length];
            unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
            Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length);
            Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

            //UTF8Encoding utf8 = new UTF8Encoding();
            //byte[] psbytes = utf8.GetBytes(pswd);

            // --- contatenate salt and pswd bytes into fixed data array ---
            byte[] data00 = new byte[psbytes.Length + salt.Length];
            Array.Copy(psbytes, data00, psbytes.Length);		//copy the pswd bytes
            Array.Copy(salt, 0, data00, psbytes.Length, salt.Length);	//concatenate the salt bytes

            // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] result = null;
            byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

            for (int j = 0; j < miter; j++)
            {
                // ----  Now hash consecutively for count times ------
                if (j == 0)
                    result = data00;   	//initialize 
                else
                {
                    Array.Copy(result, hashtarget, result.Length);
                    Array.Copy(data00, 0, hashtarget, result.Length, data00.Length);
                    result = hashtarget;
                    //Console.WriteLine("Updated new initial hash target:") ;
                    //showBytes(result) ;
                }

                for (int i = 0; i < count; i++)
                    result = md5.ComputeHash(result);
                Array.Copy(result, 0, keymaterial, j * HASHLENGTH, result.Length);  //contatenate to keymaterial
            }
            //showBytes("Final key material", keymaterial);
            byte[] deskey = new byte[24];
            Array.Copy(keymaterial, deskey, deskey.Length);

            Array.Clear(psbytes, 0, psbytes.Length);
            Array.Clear(data00, 0, data00.Length);
            Array.Clear(result, 0, result.Length);
            Array.Clear(hashtarget, 0, hashtarget.Length);
            Array.Clear(keymaterial, 0, keymaterial.Length);

            return deskey;
        }


        public static string EncryptString(string inputString, RSACryptoServiceProvider key)
        {
            return EncryptBytes(Encoding.UTF32.GetBytes(inputString), key);
        }
        public static string EncryptBytes(byte[] bytes, RSACryptoServiceProvider key)
        {
            // TODO: Add Proper Exception Handlers
            //RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
            //rsaCryptoServiceProvider.FromXmlString(xmlString);
            //int keySize = dwKeySize / 8;
            int keySize = key.KeySize / 8;
             
            // The hash function in use by the .NET RSACryptoServiceProvider here is SHA1
            // int maxLength = ( keySize ) - 2 - ( 2 * SHA1.Create().ComputeHash( rawBytes ).Length );
            int maxLength = keySize - 42;
            int dataLength = bytes.Length;
            int iterations = dataLength / maxLength;
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i <= iterations; i++)
            {
                byte[] tempBytes = new byte[(dataLength - maxLength * i > maxLength) ? maxLength : dataLength - maxLength * i];
                Buffer.BlockCopy(bytes, maxLength * i, tempBytes, 0, tempBytes.Length);
                byte[] encryptedBytes = key.Encrypt(tempBytes, true);
                // Be aware the RSACryptoServiceProvider reverses the order of encrypted bytes after encryption and before decryption.
                // If you do not require compatibility with Microsoft Cryptographic API (CAPI) and/or other vendors.
                // Comment out the next line and the corresponding one in the DecryptString function.
                Array.Reverse(encryptedBytes);
                // Why convert to base 64?
                // Because it is the largest power-of-two base printable using only ASCII characters
                stringBuilder.Append(Convert.ToBase64String(encryptedBytes));
            }
            return stringBuilder.ToString();
        }
        public static string DecryptString(string inputString, RSACryptoServiceProvider key)
        {
            return Encoding.UTF32.GetString(DecryptBytes(inputString,key));
        }
        public static byte[] DecryptBytes(string inputString, RSACryptoServiceProvider key)
        {
            // TODO: Add Proper Exception Handlers
            //RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
            //rsaCryptoServiceProvider.FromXmlString(xmlString); 
            int base64BlockSize = ((key.KeySize / 8) % 3 != 0) ? (((key.KeySize / 8) / 3) * 4) + 4 : ((key.KeySize / 8) / 3) * 4;
            int iterations = inputString.Length / base64BlockSize;
            ArrayList arrayList = new ArrayList();
            for (int i = 0; i < iterations; i++)
            {
                byte[] encryptedBytes = Convert.FromBase64String(inputString.Substring(base64BlockSize * i, base64BlockSize));
                // Be aware the RSACryptoServiceProvider reverses the order of encrypted bytes after encryption and before decryption.
                // If you do not require compatibility with Microsoft Cryptographic API (CAPI) and/or other vendors.
                // Comment out the next line and the corresponding one in the EncryptString function.
                Array.Reverse(encryptedBytes);
                arrayList.AddRange(key.Decrypt(encryptedBytes, true));
            }
            return arrayList.ToArray(Type.GetType("System.Byte")) as byte[];
        }

        public static RSACryptoServiceProvider CreateRsaKeys(int keyLength = 2048)
        {
            CspParameters csp = new CspParameters();

            csp.KeyContainerName = "CSharp_easy_RSA_PEM";

            const int PROV_RSA_FULL = 1;
            csp.ProviderType = PROV_RSA_FULL;

            const int AT_KEYEXCHANGE = 1;
            // const int AT_SIGNATURE = 2;
            csp.KeyNumber = AT_KEYEXCHANGE;

            RSACryptoServiceProvider rsa =
                new RSACryptoServiceProvider(keyLength, csp);
            rsa.PersistKeyInCsp = false;
            return rsa;
        }
    }
}
