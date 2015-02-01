using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace CSharp_easy_RSA_PEM
{
    public class Helpers
    {  
        static Dictionary<PEMtypes, string> PEMs = new Dictionary<PEMtypes, string>()
        {
            {PEMtypes.PEM_X509_OLD , "X509 CERTIFICATE"},
            {PEMtypes.PEM_X509 , "CERTIFICATE"},
            {PEMtypes.PEM_X509_PAIR , "CERTIFICATE PAIR"},
            {PEMtypes.PEM_X509_TRUSTED , "TRUSTED CERTIFICATE"},
            {PEMtypes.PEM_X509_REQ_OLD , "NEW CERTIFICATE REQUEST"},
            {PEMtypes.PEM_X509_REQ , "CERTIFICATE REQUEST"},
            {PEMtypes.PEM_X509_CRL , "X509 CRL"},
            {PEMtypes.PEM_EVP_PKEY , "ANY PRIVATE KEY"},
            {PEMtypes.PEM_PUBLIC , "PUBLIC KEY"},
            {PEMtypes.PEM_RSA , "RSA PRIVATE KEY"},
            {PEMtypes.PEM_RSA_PUBLIC , "RSA PUBLIC KEY"},
            {PEMtypes.PEM_DSA , "DSA PRIVATE KEY"},
            {PEMtypes.PEM_DSA_PUBLIC , "DSA PUBLIC KEY"},
            {PEMtypes.PEM_PKCS7 , "PKCS7"},
            {PEMtypes.PEM_PKCS7_SIGNED , "PKCS #7 SIGNED DATA"},
            {PEMtypes.PEM_PKCS8 , "ENCRYPTED PRIVATE KEY"},
            {PEMtypes.PEM_PKCS8INF , "PRIVATE KEY"},
            {PEMtypes.PEM_DHPARAMS , "DH PARAMETERS"},
            {PEMtypes.PEM_SSL_SESSION , "SSL SESSION PARAMETERS"},
            {PEMtypes.PEM_DSAPARAMS , "DSA PARAMETERS"},
            {PEMtypes.PEM_ECDSA_PUBLIC , "ECDSA PUBLIC KEY"},
            {PEMtypes.PEM_ECPARAMETERS , "EC PARAMETERS"},
            {PEMtypes.PEM_ECPRIVATEKEY , "EC PRIVATE KEY"},
            {PEMtypes.PEM_CMS , "CMS"},
            {PEMtypes.PEM_SSH2_PUBLIC , "SSH2 PUBLIC KEY"},
            {PEMtypes.unknown , "UNKNOWN"}
        };
          
        /// <summary>
        /// This helper function parses an integer size from the reader using the ASN.1 format
        /// </summary>
        /// <param name="rd"></param>
        /// <returns></returns>
        public static int DecodeIntegerSize(System.IO.BinaryReader rd)
        {
            byte byteValue;
            int count;

            byteValue = rd.ReadByte();
            if (byteValue != 0x02)        // indicates an ASN.1 integer value follows
                return 0;

            byteValue = rd.ReadByte();
            if (byteValue == 0x81)
            {
                count = rd.ReadByte();    // data size is the following byte
            }
            else if (byteValue == 0x82)
            {
                byte hi = rd.ReadByte();  // data size in next 2 bytes
                byte lo = rd.ReadByte();
                count = BitConverter.ToUInt16(new[] { lo, hi }, 0);
            }
            else
            {
                count = byteValue;        // we already have the data size
            }

            //remove high order zeros in data
            while (rd.ReadByte() == 0x00)
            {
                count -= 1;
            }
            rd.BaseStream.Seek(-1, System.IO.SeekOrigin.Current);

            return count;
        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pemString"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        public static byte[] GetBytesFromPEM(string pemString)
        {
            PEMtypes keyType = getPEMType(pemString);
            Dictionary<string, string> extras;
            if (keyType == PEMtypes.unknown) return null;
            return GetBytesFromPEM(pemString, keyType,out extras);
        }
        public static byte[] GetBytesFromPEM(string pemString, PEMtypes type)
        {
            Dictionary<string, string> extras;
            return GetBytesFromPEM(pemString, type, out extras);
        }
        public static byte[] GetBytesFromPEM(string pemString, out Dictionary<string, string> extras)
        {
            PEMtypes type = getPEMType(pemString);
            return GetBytesFromPEM(pemString, type, out extras);
        }
        public static byte[] GetBytesFromPEM(string pemString, PEMtypes type,out Dictionary<string,string> extras)
        {
            extras = new Dictionary<string, string>();
            string header; string footer;
            string data="";
            header = PEMheader(type);
            footer = PEMfooter(type);
            
            foreach(string s in pemString.Replace("\r","").Split('\n'))
            {
                if (s.Contains(":"))
                {
                    extras.Add(s.Substring(0, s.IndexOf(":") - 1), s.Substring(s.IndexOf(":") + 1));
                }
                else
                {
                    if (s !="") data += s + "\n";
                }
            }

            int start = data.IndexOf(header) + header.Length; 
            int end = data.IndexOf(footer, start) - start;

            return Convert.FromBase64String(data.Substring(start, end));
        }

        public static PEMtypes getPEMType(string pemString)
        {
            foreach (PEMtypes d in Enum.GetValues(typeof(PEMtypes)))
            {
                if (pemString.Contains(PEMheader(d)) && pemString.Contains(PEMfooter(d))) return d;
            }
            return PEMtypes.unknown;
        }

        public static string PEMheader(PEMtypes p)
        {
            if (p == PEMtypes.PEM_SSH2_PUBLIC)
            { 
                return "---- BEGIN " + PEMs[p] + " ----";
            }
            else
            {
                return "-----BEGIN " + PEMs[p] + "-----";
            }
        }
        public static string PEMfooter(PEMtypes p)
        {
            if (p == PEMtypes.PEM_SSH2_PUBLIC)
            {
                return "---- END " + PEMs[p] + " ----";
            }
            else
            {
                return "-----END " + PEMs[p] + "-----";
            }
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <param name="alignSize"></param>
        /// <returns></returns>
        public static byte[] AlignBytes(byte[] inputBytes, int alignSize)
        {
            int inputBytesSize = inputBytes.Length;

            if ((alignSize != -1) && (inputBytesSize < alignSize))
            {
                byte[] buf = new byte[alignSize];
                for (int i = 0; i < inputBytesSize; ++i)
                {
                    buf[i + (alignSize - inputBytesSize)] = inputBytes[i];
                }
                return buf;
            }
            else
            {
                return inputBytes;      // Already aligned, or doesn't need alignment
            }
        }

        public static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
        public static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        public static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
    }
}
