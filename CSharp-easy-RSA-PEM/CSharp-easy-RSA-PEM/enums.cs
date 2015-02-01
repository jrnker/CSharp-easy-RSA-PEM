using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CSharp_easy_RSA_PEM
{

    public enum PEMtypes
    {
        PEM_X509_OLD,
        PEM_X509,
        PEM_X509_PAIR,
        PEM_X509_TRUSTED,
        PEM_X509_REQ_OLD,
        PEM_X509_REQ,
        PEM_X509_CRL,
        PEM_EVP_PKEY,
        PEM_PUBLIC,
        PEM_RSA,
        PEM_RSA_PUBLIC,
        PEM_DSA,
        PEM_DSA_PUBLIC,
        PEM_PKCS7,
        PEM_PKCS7_SIGNED,
        PEM_PKCS8,
        PEM_PKCS8INF,
        PEM_DHPARAMS,
        PEM_SSL_SESSION,
        PEM_DSAPARAMS,
        PEM_ECDSA_PUBLIC,
        PEM_ECPARAMETERS,
        PEM_ECPRIVATEKEY,
        PEM_CMS,
        PEM_SSH2_PUBLIC,
        unknown
    }
}
