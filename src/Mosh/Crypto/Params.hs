module Mosh.Crypto.Params where

import Mosh.Crypto.Key

-- base
import Control.Monad
import Data.Bits
import Data.Monoid

-- bytestring
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- cipher-aes128
import Crypto.Cipher.AES128


cbBlock, cbTag :: Int
cbBlock = 16
cbTag = 16


data OcbParams = OcbParams {
        ocbKey :: OcbKey
      , ocbBottom :: Int
      , ocbKTop :: ByteString
      , ocbStretch :: ByteString
      }

ocbOffset0 :: OcbParams -> ByteString
ocbOffset0 OcbParams{..} = B.take cbBlock $ dropBits ocbBottom ocbStretch

buildOcbParams :: OcbKey -> ByteString -> Maybe OcbParams
buildOcbParams ocbKey bsNonce = do
        let cb = B.length bsNonce
        guard $ cb < 16
        let nonce128 = B.take (15 - cb) zeroes <> B.cons 1 bsNonce
            ocbBottom = fromIntegral $ B.last nonce128 .&. 63
            ocbKTop = encryptBlock (ocbCipherKey ocbKey)
                      $ B.init nonce128 <> B.singleton (B.last nonce128 .&. 192)
            ocbStretch = ocbKTop <> xorBS (B.take 8 ocbKTop)
                                          (B.take 8 $ B.drop 1 ocbKTop)
        return OcbParams{..}

ocbEncryptBlock, ocbDecryptBlock :: OcbParams -> ByteString -> ByteString
ocbEncryptBlock = encryptBlock . ocbCipherKey . ocbKey
ocbDecryptBlock = decryptBlock . ocbCipherKey . ocbKey
