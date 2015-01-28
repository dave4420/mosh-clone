module Mosh.Crypto.Key where

-- base
import Control.Applicative
import Data.Bits

-- bytestring
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- cereal
import Data.Serialize as DS

-- cipher-aes128
import Crypto.Cipher.AES128

-- lens
import Control.Lens
import Data.Bits.Lens


data OcbKey = OcbKey {
        ocbCipherKey :: AESKey128
      , ocbLStar :: ByteString
      , ocbLDollar :: ByteString
      , ocbLs :: [ByteString]
      }

ocbLAt :: OcbKey -> Int -> ByteString
ocbLAt OcbKey{..} i = ocbLs !! i

mkOcbKey :: AESKey128 -> OcbKey
mkOcbKey ocbCipherKey = OcbKey{..} where
        ocbLStar = encryptBlock ocbCipherKey zeroes
        ocbLDollar = double ocbLStar
        ocbLs = iterate double (double ocbLDollar)

buildOcbKey :: ByteString -> Maybe OcbKey
buildOcbKey = fmap mkOcbKey . buildKey

instance DS.Serialize OcbKey where
        put = DS.put . ocbCipherKey
        get = mkOcbKey <$> DS.get


zeroes :: ByteString
zeroes = B.pack $ replicate 16 0

-- The RFC calls out this function as being the only part of the algorithm
-- vulnerable to timing attacks, so attempt to avoid them.
double :: ByteString -> ByteString
double bs = dropBits 1 (B.snoc bs 0)
            `xorBS` B.pack (replicate 15 0
                            ++ [if B.head bs ^. bitAt 7 then 0x87 else 0])

dropBits :: Int -> ByteString -> ByteString
dropBits n = f . B.drop nBytes where
        (nBytes, nBits) = n `divMod` 8
        f | nBits == 0 = id
          | otherwise  = B.pack . (B.zipWith g <*> B.drop 1)
        g x y = shiftL x nBits .|. shiftR y (8 - nBits)

xorBS :: ByteString -> ByteString -> ByteString
xorBS xs ys = B.pack $ B.zipWith xor xs ys
