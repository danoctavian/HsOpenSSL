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
import Foreign.Storable
import Foreign.Marshal.Alloc
import OpenSSL.Utils

import Data.ByteString
import qualified Data.ByteString.Char8 as B8

import OpenSSL.X509.Name
import OpenSSL.X509


writeX509DER :: X509 -> IO ByteString
writeX509DER cert
  = withX509Ptr cert $ \certPtr -> do
      -- a pointer to the pointer of the beginning of the buffer
      output <- malloc :: IO (Ptr (Ptr (CChar)))
      -- set it to null
      poke output nullPtr

      let cleanup = free output

      len <- _i2d_X509 certPtr output

      if (len <= 0)
        then do
          cleanup
          raiseOpenSSLError
        else do
          bsPtr <- peek output
          bs <- B8.packCStringLen (bsPtr, fromIntegral len)
          free bsPtr
          cleanup
          return bs

readX509DER :: ByteString -> IO (Maybe X509)
readX509DER bs
  = useAsCStringLen bs $ \(buf, len) -> do
      input <- malloc :: IO (Ptr (Ptr (CChar)))
      -- set it to point to the buffer
      poke input buf

      result <- _d2i_X509 nullPtr input (fromIntegral len)

      final <- if (result == nullPtr)
        then return Nothing
        else fmap Just $ wrapX509 result
      free input
      return final

-- X509 *d2i_X509(X509 **px, const unsigned char **in, int len);
foreign import ccall safe "d2i_X509"
        _d2i_X509 :: Ptr (Ptr X509_)
                       -> Ptr (Ptr CChar)
                       -> CInt
                       -> IO (Ptr X509_)

--  int i2d_X509(X509 *x, unsigned char **out);
foreign import ccall safe "i2d_X509"
        _i2d_X509 :: Ptr X509_
                       -> Ptr (Ptr CChar)
                       -> IO CInt

{- MODEL 


X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);

foreign import ccall safe "PEM_read_bio_X509"
        _read_bio_X509 :: Ptr BIO_
                       -> Ptr (Ptr X509_)
                       -> FunPtr PemPasswordCallback'
                       -> Ptr ()
                       -> IO (Ptr X509_)

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
