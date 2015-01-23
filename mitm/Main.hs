import Mosh

-- aeson
import qualified Data.Aeson as J

-- async
import Control.Concurrent.Async

-- base
import Control.Applicative
import Control.Concurrent (threadDelay)
import Control.Exception (bracket)
import Control.Monad
import Data.List
import Data.Monoid
import System.Environment (getArgs)
import System.IO

-- base64-bytestring
import qualified Data.ByteString.Base64 as B64

-- bytestring
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

-- cereal
import Data.Serialize

-- daemons
import System.Posix.Daemon

-- errors
import Control.Error

-- network
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString

-- lens
import Control.Lens

-- pipes
import Pipes
import qualified Pipes.Prelude as P

-- pipes-aeson
import qualified Pipes.Aeson as PJ

-- pipes-bytestring
import qualified Pipes.ByteString as PB

-- process
import System.Process

-- text
import Data.Text (Text)

-- unordered-containers
import qualified Data.HashMap.Strict as HM


type LogEntry = J.Object
type LogT = Producer LogEntry
type LogIO = LogT IO

(-:) :: J.ToJSON json => Text -> json -> Maybe (Text, J.Value)
key -: value = Just (key, J.toJSON value)

(--:) :: Text -> Text -> Maybe (Text, J.Value)
(--:) = (-:)

(-?:) :: J.ToJSON json => Text -> Maybe json -> Maybe (Text, J.Value)
key -?: value = (key -:) =<< value

logM :: Monad m => [Maybe (Text, J.Value)] -> LogT m ()
logM = yield . HM.fromList . catMaybes

logToFile :: String -> LogT IO a -> IO a
logToFile nf process
        = bracket (openFile nf AppendMode) hClose
          $ \h -> do
                hSetBuffering h LineBuffering
                runEffect
                    $ process
                      >-> for cat PJ.encodeObject
                      >-> P.map (<> "\n")
                      >-> PB.toHandle h


$(declareLenses [d|
        data ToClient = ToClient {
                clientSocket :: Socket -- ^ disconnected UDP socket
              , clientAddress :: Maybe SockAddr
        }
  |])

type ToServer = Socket -- ^ connected UDP socket


startRemoteServer :: [String] -> IO (OcbKey, ToServer)
startRemoteServer args = do
        (_hInMay, hOutMay, hErrMay, hProc)
         <- createProcess (proc "mosh-server" args) {std_out = CreatePipe,
                                                     std_err = CreatePipe}
        hOut
         <- maybe (fail "stdout from mosh-server not captured") return hOutMay
        hErr
         <- maybe (fail "stderr from mosh-server not captured") return hErrMay
        (bsOut, bsErr)
         <- runConcurrently $ (,) <$> Concurrently (B.hGetContents hOut)
                                  <*> Concurrently (B.hGetContents hErr)
        -- `mosh` script interleaves stdout and stderr from `mosh-server`,
        -- and looks in the combined output for the MOSH CONNECT line
        _exitCode <- waitForProcess hProc
        (port, sharedEncryptionKey)
         <- maybe (fail "MOSH CONNECT line not received from server") return
            $ parseConnectLine bsOut <|> parseConnectLine bsErr
        sock <- socket AF_INET Datagram defaultProtocol
        connect sock $ SockAddrInet port iNADDR_ANY
        return (sharedEncryptionKey, sock)
    where
        parseConnectLine
                = headMay
                  . mapMaybe (f . dropWhileEnd B.null . BC.splitWith (== ' '))
                  . BC.splitWith (\ch -> ch == '\n' || ch == '\r')
            where
                f ["MOSH", "CONNECT", bsPort, bsKey]
                    = (,) <$> parsePort bsPort <*> parseKey bsKey
                f _ = Nothing
        parsePort :: ByteString -> Maybe PortNumber
        parsePort bs = do
                guard (B.length bs <= 5)
                port <- readMay (BC.unpack bs)
                guard (1 <= port && port <= 65535)
                return $ fromInteger port
        parseKey :: ByteString -> Maybe OcbKey
        parseKey bs = do
                guard (B.length bs == 22)
                hush . decode . B64.decodeLenient $ bs

startLocalServer :: OcbKey -> IO ToClient
startLocalServer key = do
        sock <- socket AF_INET Datagram defaultProtocol
        bind sock $ SockAddrInet (PortNum 0) 0
        B.putStr . message =<< socketPort sock
        return $ ToClient sock Nothing
    where
        message port = BC.unlines [
                "",
                BC.unwords [
                        "MOSH CONNECT",
                        (BC.pack . show) port,
                        (BC.takeWhile (/= '=')
                         . B64.encode
                         . Data.Serialize.encode) key],
                "",
                "This is mosh-mitm."]

relay :: OcbKey -> ToServer -> ToClient -> LogIO ()
relay key server client = join . lift . runConcurrently
        $ return () <$ Concurrently (threadDelay 1000000000 {-MICROseconds-})
          <|> onPacketFromClient
              <$> Concurrently (recvFrom (client ^. clientSocket) 4096)
          <|> onPacketFromServer <$> Concurrently (recv server 4096)
    where
        onPacketFromClient (packet, newAddress) = do
                cbSent <- lift $ send server packet
                logIt "client-server" packet cbSent
                relay key server (clientAddress .~ Just newAddress $ client)
        onPacketFromServer packet = do
                cbSent
                 <- maybe (return 0)
                          (lift . sendTo (client ^. clientSocket) packet)
                    $ client ^. clientAddress
                logIt "server-client" packet cbSent
                relay key server client
        logIt direction bs cbSent
                = logM ["what" --: "relayed UDP packet",
                        "direction" --: direction,
                        "count-bytes-received" -: B.length bs,
                        "count-bytes-sent" -: cbSent,
                        "packet-decoding-error" -?: packetDecodingError,
                        "nonce" -?: (fmap . view) packetNonce packet,
                        "packet-payload-decoding-error"
                            -?: packetPayloadDecodingError,
                        "packet-payload" -?: packetPayload_]
            where
                packet' = decode bs
                packetDecodingError = (hush . flipE) packet'
                packet = hush packet' :: Maybe Packet
                packetPayload' :: Maybe (Either String PacketPayload)
                packetPayload' = do
                        p <- packet
                        bs' <- ocbAesDecrypt
                                key
                                (p ^. packetNonce)
                                (p ^. packetPayload)
                        return . decode $ bs'
                packetPayloadDecodingError = hush . flipE =<< packetPayload'
                packetPayload_ = hush =<< packetPayload' :: Maybe PacketPayload


main :: IO ()
main = withSocketsDo $ do
        (key, remoteServer) <- startRemoteServer =<< getArgs
        localServer <- startLocalServer key
        runDetached Nothing DevNull
            . logToFile "/home/dave/tmp/mosh-mitm.log"
            $ relay key remoteServer localServer

