{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CPP                      #-}

module OpenSSL.X509.DER
    ( writeX509DER
    , readX509DER
    )
    where

import Control.Monad
import Data.Time.Clock
import Data.Maybe
import Foreign.ForeignPtr
#if MIN_VERSION_base(4,4,0)
import Foreign.ForeignPtr.Unsafe as Unsafe
#else
import Foreign.ForeignPtr as Unsafe
#endif
import Foreign.Ptr
import Foreign.C
import OpenSSL.ASN1
import OpenSSL.BIO
{-
import OpenSSL.EVP.Digest
import OpenSSL.EVP.PKey
import OpenSSL.EVP.Verify
import OpenSSL.EVP.Internal
import OpenSSL.Utils
import OpenSSL.Stack
-}
import OpenSSL.X509.Name
import OpenSSL.X509


writeX509DER :: X509 -> IO String
writeX509DER cert = undefined

readX509DER :: String -> Maybe X509
readX509DER str = undefined

{- MODEL 

how to use this funtion.

foreign import ccall unsafe "EVP_SealInit"
        _SealInit :: Ptr EVP_CIPHER_CTX
                  -> Cipher
                  -> Ptr (Ptr CChar)
                  -> Ptr CInt
                  -> CString
                  -> Ptr (Ptr EVP_PKEY)
                  -> CInt
                  -> IO CInt

sealInit cipher pubKeys
    = do ctx <- newCipherCtx

         -- Allocate a list of buffers to write encrypted symmetric
         -- keys. Each keys will be at most pkeySize bytes long.
         encKeyBufs <- mapM mallocEncKeyBuf pubKeys

         -- encKeyBufs is [Ptr a] but we want Ptr (Ptr CChar).
         encKeyBufsPtr <- newArray encKeyBufs

         -- Allocate a buffer to write lengths of each enc_SealInitrypted
         -- symmetric keys.
         encKeyBufsLenPtr <- mallocArray nKeys

         -- Allocate a buffer to write IV.
         ivPtr <- mallocArray (cipherIvLength cipher)

         -- Create Ptr (Ptr EVP_PKEY) from [PKey]. Don't forget to
         -- apply touchForeignPtr to each PKey's later.
         pkeys      <- mapM toPKey pubKeys
         pubKeysPtr <- newArray $ map unsafePKeyToPtr pkeys

         -- Prepare an IO action to free buffers we allocated above.
         let cleanup = do mapM_ free encKeyBufs
                          free encKeyBufsPtr
                          free encKeyBufsLenPtr
                          free ivPtr
                          free pubKeysPtr
                          mapM_ touchPKey pkeys

         -- Call EVP_SealInit finally.
         ret <- withCipherCtxPtr ctx $ \ ctxPtr ->
                _SealInit ctxPtr cipher encKeyBufsPtr encKeyBufsLenPtr ivPtr pubKeysPtr (fromIntegral nKeys)

-}
