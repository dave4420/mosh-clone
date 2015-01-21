module Mosh where

-- aeson
import qualified Data.Aeson as J

-- base
import Control.Applicative
import Control.Monad
import Data.Bits
import Data.Word

-- bytestring
import Data.ByteString (ByteString)

-- cereal
import Data.Serialize

-- lens
import Control.Lens
import Data.Bits.Lens


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
                put (the ^. packetNonce)
                putByteString (the ^. packetPayload)
        get = Packet <$> get <*> getRemainingByteString


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
