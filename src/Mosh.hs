module Mosh (
        module Mosh,
        OcbKey,
)
where

import Mosh.Crypto.Key

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
import Crypto.Cipher.AES128

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


newtype Nonce = Nonce Word64

nonce :: Peer -> Word64 -> Maybe Nonce
nonce peer counter = do
        guard $ counter .&. bit 63 == 0
        return . Nonce . (bitAt 63 .~ (peer == Client)) $ counter

nonceCounter :: Getter Nonce Word64
nonceCounter = to $ \(Nonce n) -> bitAt 63 .~ False $ n

nonceDest :: Getter Nonce Peer
nonceDest = to $ \(Nonce n) -> if n ^. bitAt 63 then Client else Server

instance Serialize Nonce where
        put (Nonce n) = putWord64be n
        get = Nonce <$> getWord64be

instance J.ToJSON Nonce where
        toJSON n = J.object ["dest" J..= (n ^. nonceDest),
                             "counter" J..= (n ^. nonceCounter)]


$(declareLenses [d|
        data Packet = Packet {
                packetNonce :: Nonce
              , packetPayload :: ByteString
        }
  |])

instance Serialize Packet where
        put the = do
                DS.put (the ^. packetNonce)
                putByteString (the ^. packetPayload)
        get = Packet <$> DS.get <*> getRemainingByteString


$(declareLenses [d|
        data PacketPayload = PacketPayload {
                packetPayloadSender'sTimer :: Word16
              , packetPayloadLastTimerSenderReceived :: Word16
              , packetPayloadPayload :: ByteString
        }
  |])

instance Serialize PacketPayload where
        put the = do
                putWord16be (the ^. packetPayloadSender'sTimer)
                putWord16be (the ^. packetPayloadLastTimerSenderReceived)
                putByteString (the ^. packetPayloadPayload)
        get = PacketPayload <$> getWord16be
                            <*> getWord16be
                            <*> getRemainingByteString

instance J.ToJSON PacketPayload where
        toJSON the
            = J.object ["senders-timer"
                            J..= (the ^. packetPayloadSender'sTimer),
                        "last-timer-sender-received"
                            J..= (the ^. packetPayloadLastTimerSenderReceived),
                        "payload-length"
                            J..= B.length (the ^. packetPayloadPayload)]

{-
$(declareLenses [d|
        data Fragment = Fragment {
                fragmentInstructionID :: Word64
              , fragmentID :: Word16
              , fragmentIsFinal :: Bool
              , fragmentPayload :: ByteString
        }
  |])

instance Serialize Fragment where
        put the = do
                putWord64be (the ^. fragmentInstructionID)
                putWord16be ((the ^. fragmentID)
                             .|. (if the ^. fragmentIsFinal then 0x8000 else 0))
                putByteString (the ^. fragmentPayload)
        get = do
                iid <- getWord64be
                fid <- getWord16be
                payload <- getRemainingByteString
                return $ Fragment iid (fid .&. 0x7fff) (testBit fid 15) payload
-}


-- OCB encryption is described in RFC 7253.

-- | Hardcoding:
--    *  key length = 128 bits
--    *  nonce length = 96 bits
--        *  method of expanding nonce from 64 bits
--    *  no associated data
--    *  tag length = 128 bits

ocbAesEncrypt :: OcbKey -> Nonce -> ByteString -> ByteString
ocbAesEncrypt key = ocbAesEncrypt' key . expandNonce

ocbAesEncrypt' :: OcbKey -> ByteString -> ByteString -> ByteString
ocbAesEncrypt' key nonce96 plaintext = let
        (plains, plainStar) = slicePlaintext plaintext
        (ciphers, cipherStar, tag)
                = flip evalState (offset0, checksum0)
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
                                  `xorBS` encryptBlock
                                          (ocbKey key)
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
                    pad = encryptBlock (ocbKey key) nextOffset
                    cipherStar = plainStar `xorBS` pad
                    nextChecksum = traceBS "Checksum_*" $
                                   prevChecksum
                                   `xorBS` (plainStar <> B.cons 128 zeroes)
                S.put (nextOffset, nextChecksum)
                return cipherStar

        computeTag = do
                (offset, checksum) <- S.get
                return . encryptBlock (ocbKey key)
                    $ checksum `xorBS` offset `xorBS` ocbLDollar key

        -- nonce-derived values
        nonce128 = B.pack [0,0,0,1] <> nonce96
        bottom = traceVar "bottom" . fromIntegral $ B.last nonce128 .&. 63
        kTop = traceBS "kTop:" $
               encryptBlock (ocbKey key) $
               B.init nonce128 <> B.singleton (B.last nonce128 .&. 192)
        stretch = traceBS "stretch:" $
                  kTop <> B.pack (B.zipWith xor (B.take 8 kTop)
                                                (B.take 8 $ B.drop 1 kTop))
        offset0 = traceBS "Offset_0" $
                  B.take cbBlock $ dropBits bottom stretch
        checksum0 = zeroes


ocbAesDecrypt :: OcbKey -> Nonce -> ByteString -> Maybe ByteString
ocbAesDecrypt key = ocbAesDecrypt' key . expandNonce

ocbAesDecrypt' :: OcbKey -> ByteString -> ByteString -> Maybe ByteString
ocbAesDecrypt' key nonce96 cryptotext = do
        (cryptos, cryptoStar, givenTag) <- sliceCiphertext cryptotext
        let (plains, plainStar, computedTag)
                = flip evalState (offset0, checksum0)
                  $ (,,) <$> zipWithM round' cryptos [1..]
                         <*> finalRound cryptoStar
                         <*> computeTag
        guard $ traceBS "tag" computedTag == givenTag
        return . traceBS "plaintext" $ mconcat plains <> plainStar
    where

        round' cipherblock i = do
                (prevOffset, prevChecksum) <- S.get
                let nextOffset = traceBS ("Offset_" ++ show i) $
                                 prevOffset `xorBS` (ocbLAt key (ntz i))
                    plainblock = nextOffset
                                 `xorBS` decryptBlock
                                         (ocbKey key)
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
                    pad = encryptBlock (ocbKey key) nextOffset
                    plainStar = cipherblock `xorBS` pad
                    nextChecksum = traceBS "Checksum_*" $
                                   prevChecksum
                                   `xorBS` (plainStar <> B.cons 128 zeroes)
                S.put (nextOffset, nextChecksum)
                return plainStar

        computeTag = do
                (offset, checksum) <- S.get
                return . encryptBlock (ocbKey key)
                    $ checksum `xorBS` offset `xorBS` ocbLDollar key

        -- nonce-derived values
        nonce128 = B.pack [0,0,0,1] <> nonce96
        bottom = traceVar "bottom" . fromIntegral $ B.last nonce128 .&. 63
        kTop = traceBS "kTop:" $
               encryptBlock (ocbKey key) $
               B.init nonce128 <> B.singleton (B.last nonce128 .&. 192)
        stretch = traceBS "stretch:" $
                  kTop <> B.pack (B.zipWith xor (B.take 8 kTop)
                                                (B.take 8 $ B.drop 1 kTop))
        offset0 = traceBS "Offset_0" $
                  B.take cbBlock $ dropBits bottom stretch
        checksum0 = zeroes


-- | number of trailing zero bits
ntz :: Int -> Int
ntz n = f 0 where
        f i | n ^. bitAt i = i
            | otherwise    = f (i + 1)


expandNonce :: Nonce -> ByteString
expandNonce nonce64 = B.pack (replicate 4 0) <> encode nonce64


cbBlock, cbTag :: Int
cbBlock = 16
cbTag = 16

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
