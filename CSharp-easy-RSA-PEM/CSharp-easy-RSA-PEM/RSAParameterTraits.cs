using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CSharp_easy_RSA_PEM
{
    internal class RSAParameterTraits
    {
        public RSAParameterTraits(int modulusLengthInBits)
        {
            // The modulus length is supposed to be one of the common lengths, which is the commonly referred to strength of the key,
            // like 1024 bit, 2048 bit, etc.  It might be a few bits off though, since if the modulus has leading zeros it could show
            // up as 1016 bits or something like that.
            int assumedLength = -1;
            double logbase = Math.Log(modulusLengthInBits, 2);
            if (logbase == (int)logbase)
            {
                // It's already an even power of 2
                assumedLength = modulusLengthInBits;
            }
            else
            {
                // It's not an even power of 2, so round it up to the nearest power of 2.
                assumedLength = (int)(logbase + 1.0);
                assumedLength = (int)(Math.Pow(2, assumedLength));
                System.Diagnostics.Debug.Assert(false);  // Can this really happen in the field?  I've never seen it, so if it happens
                // you should verify that this really does the 'right' thing!
            }

            switch (assumedLength)
            {
                case 512:
                    this.size_Mod = 0x40;
                    this.size_Exp = -1;
                    this.size_D = 0x40;
                    this.size_P = 0x20;
                    this.size_Q = 0x20;
                    this.size_DP = 0x20;
                    this.size_DQ = 0x20;
                    this.size_InvQ = 0x20;
                    break;
                case 1024:
                    this.size_Mod = 0x80;
                    this.size_Exp = -1;
                    this.size_D = 0x80;
                    this.size_P = 0x40;
                    this.size_Q = 0x40;
                    this.size_DP = 0x40;
                    this.size_DQ = 0x40;
                    this.size_InvQ = 0x40;
                    break;
                case 2048:
                    this.size_Mod = 0x100;
                    this.size_Exp = -1;
                    this.size_D = 0x100;
                    this.size_P = 0x80;
                    this.size_Q = 0x80;
                    this.size_DP = 0x80;
                    this.size_DQ = 0x80;
                    this.size_InvQ = 0x80;
                    break;
                case 4096:
                    this.size_Mod = 0x200;
                    this.size_Exp = -1;
                    this.size_D = 0x200;
                    this.size_P = 0x100;
                    this.size_Q = 0x100;
                    this.size_DP = 0x100;
                    this.size_DQ = 0x100;
                    this.size_InvQ = 0x100;
                    break;
                default:
                    System.Diagnostics.Debug.Assert(false); // Unknown key size?
                    break;
            }
        }

        public int size_Mod  = -1;
        public int size_Exp  = -1;
        public int size_D    = -1;
        public int size_P    = -1;
        public int size_Q    = -1;
        public int size_DP   = -1;
        public int size_DQ   = -1;
        public int size_InvQ = -1;
    }
}
