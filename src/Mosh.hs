module Mosh (
        module Mosh,
        OcbKey,
        buildOcbParams,
)
where

import Mosh.Crypto.Key
import Mosh.Crypto.Params

-- aeson
import qualified Data.Aeson as J

-- base
import Control.Applicative
import Control.Monad
import Data.Bits
import Data.List
import Data.Monoid
import Data.Word
import Debug.Trace

-- bytestring
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- cereal
import Data.Serialize as DS

-- cipher-aes128
--import Crypto.Cipher.AES128

-- lens
import Control.Lens
import Data.Bits.Lens

-- transformers
import Control.Monad.Trans.State.Strict as S


getRemainingByteString :: Get ByteString
getRemainingByteString = getBytes =<< remaining


data Peer = Server | Client deriving Eq

instance J.ToJSON Peer where
        toJSON Server = J.String "server"
        toJSON Client = J.String "client"


newtype MoshNonce = MoshNonce Word64

moshNonce :: Peer -> Word64 -> Maybe MoshNonce
moshNonce peer counter = do
        guard $ counter .&. bit 63 == 0
        return . MoshNonce . (bitAt 63 .~ (peer == Client)) $ counter

nonceCounter :: Getter MoshNonce Word64
nonceCounter = to $ \(MoshNonce n) -> bitAt 63 .~ False $ n

nonceDest :: Getter MoshNonce Peer
nonceDest = to $ \(MoshNonce n) -> if n ^. bitAt 63 then Client else Server

instance Serialize MoshNonce where
        put (MoshNonce n) = putWord64be n
        get = MoshNonce <$> getWord64be

instance J.ToJSON MoshNonce where
        toJSON n = J.object ["dest" J..= (n ^. nonceDest),
                             "counter" J..= (n ^. nonceCounter)]


$(declareLenses [d|
        data Packet = Packet {
                packetNonce :: MoshNonce
              , packetPayload :: ByteString
        }
  |])

instance Serialize Packet where
        put the = do
                DS.put (the ^. packetNonce)
                putByteString (the ^. packetPayload)
        get = Packet <$> DS.get <*> getRemainingByteString


-- | In the original mosh, the timers are not considered part of the fragment.
$(declareLenses [d|
        data Fragment = Fragment {
                fragmentSender'sTimer :: Word16
              , fragmentLastTimerSenderReceived :: Word16
              , fragmentInstructionID :: Word64
              , fragmentID :: Word16
              , fragmentIsFinal :: Bool
              , fragmentPayload :: ByteString
        }
  |])

instance Serialize Fragment where
        put the = do
                putWord16be (the ^. fragmentSender'sTimer)
                putWord16be (the ^. fragmentLastTimerSenderReceived)
                putWord64be (the ^. fragmentInstructionID)
                putWord16be ((the ^. fragmentID)
                             .|. (if the ^. fragmentIsFinal then 0x8000 else 0))
                putByteString (the ^. fragmentPayload)
        get = do
                tSender <- getWord16be
                tReceived <- getWord16be
                iid <- getWord64be
                fid <- getWord16be
                payload <- getRemainingByteString
                return $ Fragment tSender tReceived iid (fid .&. 0x7fff)
                                  (testBit fid 15) payload

instance J.ToJSON Fragment where
        toJSON the
            = J.object ["senders-timer"
                            J..= (the ^. fragmentSender'sTimer),
                        "last-timer-sender-received"
                            J..= (the ^. fragmentLastTimerSenderReceived),
                        "instruction-id"
                            J..= (the ^. fragmentInstructionID),
                        "id"
                            J..= (the ^. fragmentID),
                        "is-final"
                            J..= (the ^. fragmentIsFinal),
                        "payload-length"
                            J..= B.length (the ^. fragmentPayload)]


-- OCB encryption is described in RFC 7253.

-- | Hardcoding:
--    *  key length = 128 bits
--    *  nonce length = 96 bits
--        *  method of expanding nonce from 64 bits
--    *  no associated data
--    *  tag length = 128 bits

ocbAesEncrypt :: OcbParams -> ByteString -> ByteString
ocbAesEncrypt param plaintext = let
        (plains, plainStar) = slicePlaintext plaintext
        (ciphers, cipherStar, tag)
                = flip evalState (ocbOffset0 param, zeroes)
                  $ (,,) <$> zipWithM round' plains [1..]
                         <*> finalRound plainStar
                         <*> computeTag
      in mconcat ciphers <> cipherStar <> tag
    where

        round' plainblock i = do
                (prevOffset, prevChecksum) <- S.get
                let nextOffset = traceBS ("Offset_" ++ show i) $
                                 prevOffset `xorBS` (ocbLAt key (ntz i))
                    cipherblock = nextOffset
                                  `xorBS` ocbEncryptBlock param
                                          (plainblock `xorBS` nextOffset)
                    nextChecksum = traceBS ("Checksum_" ++ show i) $
                                   prevChecksum `xorBS` plainblock
                S.put (nextOffset, nextChecksum)
                return cipherblock

        finalRound plainStar | B.null plainStar = return ""
                             | otherwise = do
                (prevOffset, prevChecksum) <- S.get
                let nextOffset = traceBS "Offset_*" $
                                 prevOffset `xorBS` ocbLStar key
                    pad = ocbEncryptBlock param nextOffset
                    cipherStar = plainStar `xorBS` pad
                    nextChecksum = traceBS "Checksum_*" $
                                   prevChecksum
                                   `xorBS` (plainStar <> B.cons 128 zeroes)
                S.put (nextOffset, nextChecksum)
                return cipherStar

        computeTag = do
                (offset, checksum) <- S.get
                return . ocbEncryptBlock param
                    $ checksum `xorBS` offset `xorBS` ocbLDollar key

        key = ocbKey param


ocbAesDecrypt :: OcbParams -> ByteString -> Maybe ByteString
ocbAesDecrypt param ciphertext = do
        (ciphers, cipherStar, givenTag) <- sliceCiphertext ciphertext
        let (plains, plainStar, computedTag)
                = flip evalState (ocbOffset0 param, zeroes)
                  $ (,,) <$> zipWithM round' ciphers [1..]
                         <*> finalRound cipherStar
                         <*> computeTag
        guard $ traceBS "tag" computedTag == givenTag
        return . traceBS "plaintext" $ mconcat plains <> plainStar
    where

        round' cipherblock i = do
                (prevOffset, prevChecksum) <- S.get
                let nextOffset = traceBS ("Offset_" ++ show i) $
                                 prevOffset `xorBS` (ocbLAt key (ntz i))
                    plainblock = nextOffset
                                 `xorBS` ocbDecryptBlock param
                                         (cipherblock `xorBS` nextOffset)
                    nextChecksum = traceBS ("Checksum_" ++ show i) $
                                   prevChecksum `xorBS` plainblock
                S.put (nextOffset, nextChecksum)
                return plainblock

        finalRound cipherblock | B.null cipherblock = return ""
                               | otherwise = do
                (prevOffset, prevChecksum) <- S.get
                let nextOffset = traceBS "Offset_*" $
                                 prevOffset `xorBS` ocbLStar key
                    pad = ocbEncryptBlock param nextOffset
                    plainStar = cipherblock `xorBS` pad
                    nextChecksum = traceBS "Checksum_*" $
                                   prevChecksum
                                   `xorBS` (plainStar <> B.cons 128 zeroes)
                S.put (nextOffset, nextChecksum)
                return plainStar

        computeTag = do
                (offset, checksum) <- S.get
                return . ocbEncryptBlock param
                    $ checksum `xorBS` offset `xorBS` ocbLDollar key

        key = ocbKey param


-- | number of trailing zero bits
ntz :: Int -> Int
ntz n = f 0 where
        f i | n ^. bitAt i = i
            | otherwise    = f (i + 1)


nonceFromMoshNonce :: MoshNonce -> ByteString
nonceFromMoshNonce nonce64 = B.pack (replicate 4 0) <> encode nonce64


sliceCiphertext :: ByteString -> Maybe ([ByteString], ByteString, ByteString)
sliceCiphertext full = do
        let cb = B.length full - cbTag
        guard $ 0 <= cb
        let (nonTag, tag) = B.splitAt cb full
            (fullSized, leftOvers) = slicePlaintext nonTag
        return (fullSized, leftOvers, tag)

slicePlaintext :: ByteString -> ([ByteString], ByteString)
slicePlaintext full
        | B.length full < cbBlock = ([], full)
        | otherwise               = (begin : rest, final) where
                (begin, cont) = B.splitAt cbBlock full
                (rest, final) = slicePlaintext cont


trace' :: String -> a -> a
trace' | tracing   = trace
       | otherwise = const id

tracing :: Bool
tracing = False

traceVar :: Show a => String -> a -> a
traceVar msg x = trace' (msg ++ " = " ++ show x) x where

traceBS :: String -> ByteString -> ByteString
traceBS message bs = trace' (message ++ showBS bs) bs

showBS :: ByteString -> String
showBS = concatMap ("\n\t" ++)
         . map (intercalate " ")
         . group' 4
         . map (intercalate ".")
         . group' 4
         . map showByte
         . B.unpack

showByte :: Word8 -> String
showByte byte = [hex high, hex low] where
        hex x | 0 <= x && x <= 9   = toEnum $ 48 + fromIntegral x
              | 10 <= x && x <= 15 = toEnum $ 55 + fromIntegral x
              | otherwise          = '-'
        (high, low) = byte `divMod` 16

group' :: Int -> [a] -> [[a]]
group' _ [] = []
group' c xs = let (ys, zs) = splitAt c xs in ys : group' c zs
