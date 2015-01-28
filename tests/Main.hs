import Mosh
import Mosh.Crypto.Key

-- base
import Control.Applicative
import Control.Monad
import Data.Monoid

-- bytestring
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- cereal
import Data.Serialize

-- errors
import Control.Error

-- QuickCheck
import           Test.QuickCheck

-- test-framework
import           Test.Framework

-- test-framework-quickcheck2
import           Test.Framework.Providers.QuickCheck2

-- test-framework-th
import           Test.Framework.TH


main :: IO ()
main = defaultMain [tests]

tests :: Test
tests = $testGroupGenerator


arbitraryByteString :: Gen ByteString
arbitraryByteString = B.pack <$> arbitrary

arbitraryByteStringLength :: Int -> Gen ByteString
arbitraryByteStringLength c = B.pack <$> replicateM c arbitrary

arbitraryByteStringMinimumLength :: Int -> Gen ByteString
arbitraryByteStringMinimumLength c
        = mappend <$> arbitraryByteStringLength c <*> arbitraryByteString

arbitraryByteStringMaximumLength :: Int -> Gen ByteString
arbitraryByteStringMaximumLength c = B.take c <$> arbitraryByteString

arbitraryKey :: Gen OcbKey
arbitraryKey
        = maybe arbitraryKey return . buildOcbKey
          =<< arbitraryByteStringLength 16


prop_packetEncodingRoundTrip :: Property
prop_packetEncodingRoundTrip = forAll (arbitraryByteStringMinimumLength 8)
        $ \bs -> Right bs === fmap encode (decode bs :: Either String Packet)

prop_packetDecodingTooShort :: Property
prop_packetDecodingTooShort = forAll (arbitraryByteStringMaximumLength 7)
        $ \bs -> isLeft (decode bs :: Either String Packet)


prop_fragmentEncodingRoundTrip :: Property
prop_fragmentEncodingRoundTrip
    = forAll (arbitraryByteStringMinimumLength 14)
        $ \bs -> Right bs === fmap encode (decode bs :: Either String Fragment)

prop_fragmentDecodingTooShort :: Property
prop_fragmentDecodingTooShort
    = forAll (arbitraryByteStringMaximumLength 13)
        $ \bs -> isLeft (decode bs :: Either String Fragment)


prop_sliceCiphertextRoundTrip :: Property
prop_sliceCiphertextRoundTrip
    = forAll (arbitraryByteStringLength =<< choose (16, 256))
        $ \bs -> maybe (property False)
                       (\(bsInits, bsLast, bsTag)
                        -> mconcat bsInits <> bsLast <> bsTag === bs)
                       (sliceCiphertext bs)

prop_sliceCiphertextCorrectLengths :: Property
prop_sliceCiphertextCorrectLengths
    = forAll (arbitraryByteStringLength =<< choose (16, 256))
        $ \bs -> maybe False
                       (\(bsInits, bsLast, bsTag)
                        -> all ((== 16) . B.length) bsInits
                           && B.length bsLast < 16
                           && B.length bsTag == 16)
                       (sliceCiphertext bs)

prop_sliceCiphertextTooShort :: Property
prop_sliceCiphertextTooShort
    = forAll (arbitraryByteStringMaximumLength 15)
        $ \bs -> isNothing (sliceCiphertext bs)


sampleKey :: OcbKey
Just sampleKey = buildOcbKey . B.pack $ [0..15]

-- (96 bit nonce, plaintext, ciphertext); associated data is empty
samples :: [(ByteString, ByteString, ByteString)]
samples = [
        (B.pack [0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00],
         B.pack [],
         B.pack [0x78, 0x54, 0x07, 0xBF, 0xFF, 0xC8, 0xAD, 0x9E,
                 0xDC, 0xC5, 0x52, 0x0A, 0xC9, 0x11, 0x1E, 0xE6]),
        (B.pack [0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x03],
         B.pack [0..7],
         B.pack [0x45, 0xDD, 0x69, 0xF8, 0xF5, 0xAA, 0xE7, 0x24,
                 0x14, 0x05, 0x4C, 0xD1, 0xF3, 0x5D, 0x82, 0x76,
                 0x0B, 0x2C, 0xD0, 0x0D, 0x2F, 0x99, 0xBF, 0xA9]),
        (B.pack [0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x06],
         B.pack [0..15],
         B.pack [0x5C, 0xE8, 0x8E, 0xC2, 0xE0, 0x69, 0x27, 0x06,
                 0xA9, 0x15, 0xC0, 0x0A, 0xEB, 0x8B, 0x23, 0x96,
                 0xF4, 0x0E, 0x1C, 0x74, 0x3F, 0x52, 0x43, 0x6B,
                 0xDF, 0x06, 0xD8, 0xFA, 0x1E, 0xCA, 0x34, 0x3D]),
        (B.pack [0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x09],
         B.pack [0..23],
         B.pack [0x22, 0x1B, 0xD0, 0xDE, 0x7F, 0xA6, 0xFE, 0x99,
                 0x3E, 0xCC, 0xD7, 0x69, 0x46, 0x0A, 0x0A, 0xF2,
                 0xD6, 0xCD, 0xED, 0x0C, 0x39, 0x5B, 0x1C, 0x3C,
                 0xE7, 0x25, 0xF3, 0x24, 0x94, 0xB9, 0xF9, 0x14,
                 0xD8, 0x5C, 0x0B, 0x1E, 0xB3, 0x83, 0x57, 0xFF]),
        (B.pack [0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x0c],
         B.pack [0..31],
         B.pack [0x29, 0x42, 0xBF, 0xC7, 0x73, 0xBD, 0xA2, 0x3C,
                 0xAB, 0xC6, 0xAC, 0xFD, 0x9B, 0xFD, 0x58, 0x35,
                 0xBD, 0x30, 0x0F, 0x09, 0x73, 0x79, 0x2E, 0xF4,
                 0x60, 0x40, 0xC5, 0x3F, 0x14, 0x32, 0xBC, 0xDF,
                 0xB5, 0xE1, 0xDD, 0xE3, 0xBC, 0x18, 0xA5, 0xF8,
                 0x40, 0xB5, 0x2E, 0x65, 0x34, 0x44, 0xD5, 0xDF]),
        (B.pack [0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x0f],
         B.pack [0..39],
         B.pack [0x44, 0x12, 0x92, 0x34, 0x93, 0xC5, 0x7D, 0x5D,
                 0xE0, 0xD7, 0x00, 0xF7, 0x53, 0xCC, 0xE0, 0xD1,
                 0xD2, 0xD9, 0x50, 0x60, 0x12, 0x2E, 0x9F, 0x15,
                 0xA5, 0xDD, 0xBF, 0xC5, 0x78, 0x7E, 0x50, 0xB5,
                 0xCC, 0x55, 0xEE, 0x50, 0x7B, 0xCB, 0x08, 0x4E,
                 0x47, 0x9A, 0xD3, 0x63, 0xAC, 0x36, 0x6B, 0x95,
                 0xA9, 0x8C, 0xA5, 0xF3, 0x00, 0x0B, 0x14, 0x79])]

prop_correctlyDecryptOcbAesSamples :: Property
prop_correctlyDecryptOcbAesSamples
        = length samples === length (filter good samples)
    where
        good (nonce96, plaintext, ciphertext)
                = maybe False good' $ buildOcbParams sampleKey nonce96
            where
                good' params = Just plaintext == ocbAesDecrypt params ciphertext

prop_correctlyEncryptOcbAesSamples :: Property
prop_correctlyEncryptOcbAesSamples
        = length samples === length (filter good samples)
    where
        good (nonce96, plaintext, ciphertext)
                = maybe False good' $ buildOcbParams sampleKey nonce96
            where
                good' params = ciphertext == ocbAesEncrypt params plaintext

prop_OcbDecryptionReversesOcbEncryption :: Property
prop_OcbDecryptionReversesOcbEncryption
        = forAll (Blind <$> arbitraryKey) $ \(Blind key) ->
          forAll (arbitraryByteStringLength 12) $ \nonce' ->
          forAll arbitraryByteString $ \plaintext ->
          maybe (property False)
                (\params -> Just plaintext
                            === ocbAesDecrypt params
                                              (ocbAesEncrypt params plaintext))
                (buildOcbParams key nonce')
