{- -*- haskell -*- -}
#include "HsOpenSSL.h"
module OpenSSL.X509.Name
    ( X509_NAME

    , allocaX509Name
    , withX509Name
    , peekX509Name
    )
    where

import           Control.Exception
import           Foreign
import           Foreign.C
import           OpenSSL.Objects
import           OpenSSL.Utils


data X509_NAME       = X509_NAME
data X509_NAME_ENTRY = X509_NAME_ENTRY

foreign import ccall unsafe "X509_NAME_new"
        _new :: IO (Ptr X509_NAME)

foreign import ccall unsafe "X509_NAME_free"
        _free :: Ptr X509_NAME -> IO ()

foreign import ccall unsafe "X509_NAME_add_entry_by_txt"
        _add_entry_by_txt :: Ptr X509_NAME -> CString -> Int -> Ptr CChar -> Int -> Int -> Int -> IO Int

foreign import ccall unsafe "X509_NAME_entry_count"
        _entry_count :: Ptr X509_NAME -> IO Int

foreign import ccall unsafe "X509_NAME_get_entry"
        _get_entry :: Ptr X509_NAME -> Int -> IO (Ptr X509_NAME_ENTRY)

foreign import ccall unsafe "X509_NAME_ENTRY_get_object"
        _ENTRY_get_object :: Ptr X509_NAME_ENTRY -> IO (Ptr ASN1_OBJECT)

foreign import ccall unsafe "X509_NAME_ENTRY_get_data"
        _ENTRY_get_data :: Ptr X509_NAME_ENTRY -> IO (Ptr ASN1_STRING)


allocaX509Name :: (Ptr X509_NAME -> IO a) -> IO a
allocaX509Name m
    = bracket _new _free m


withX509Name :: [(String, String)] -> (Ptr X509_NAME -> IO a) -> IO a
withX509Name name m
    = allocaX509Name $ \ namePtr ->
      do mapM_ (addEntry namePtr) name
         m namePtr
    where
      addEntry :: Ptr X509_NAME -> (String, String) -> IO ()
      addEntry namePtr (key, val)
          = withCString    key $ \ keyPtr ->
            withCStringLen val $ \ (valPtr, valLen) ->
            _add_entry_by_txt namePtr keyPtr (#const MBSTRING_UTF8) valPtr valLen (-1) 0
                 >>= failIf (/= 1)
                 >>  return ()


peekX509Name :: Ptr X509_NAME -> Bool -> IO [(String, String)]
peekX509Name namePtr wantLongName
    = do count <- _entry_count namePtr >>= failIf (< 0)
         mapM peekEntry $ take count [0..]
    where
      peekEntry :: Int -> IO (String, String)
      peekEntry n
          = do ent <- _get_entry namePtr n  >>= failIfNull
               obj <- _ENTRY_get_object ent >>= failIfNull
               dat <- _ENTRY_get_data   ent >>= failIfNull

               nid <- obj2nid obj
               key <- if wantLongName then
                          nid2ln nid
                      else
                          nid2sn nid
               val <- peekASN1String dat

               return (key, val)