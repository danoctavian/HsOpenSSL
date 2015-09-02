-- | Tests for DER serialization, deserialization
module Main (main) where

import OpenSSL.X509.DER
import OpenSSL.X509 (newX509)
import OpenSSL.PEM

import qualified Test.Framework as TF
import qualified Test.Framework.Providers.HUnit as TF
import Test.HUnit

test_serializeDeserializeDER :: Test
test_serializeDeserializeDER = TestCase $ do
  cert <- newX509

  expected <- writeX509 cert

  bs <- writeX509DER cert

  putStrLn $ show bs

  maybeCert <- readX509DER bs

  case maybeCert of
    Just deserialized -> do
      actual <- writeX509 deserialized
      putStrLn $ show actual
      assertBool "serialized and deserialized cert match." (actual == expected)
    Nothing -> assertBool "unparsed certificate" False

tests :: Test
tests = TestList [test_serializeDeserializeDER]

main :: IO ()
main = TF.defaultMain $ TF.hUnitTestToTests tests