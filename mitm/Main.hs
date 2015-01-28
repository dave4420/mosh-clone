import Mosh

-- aeson
import qualified Data.Aeson as J

-- async
import Control.Concurrent.Async

-- base
import Control.Applicative
import Control.Concurrent (threadDelay)
import Control.Exception (bracket)
import Control.Monad hiding (sequence)
import Data.List
import Data.Monoid
import Data.Traversable hiding (for)
import Prelude hiding (sequence)
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
type LogItem = Maybe (Text, J.Value)
type LogT = Producer LogEntry
type LogIO = LogT IO

(-:) :: J.ToJSON json => Text -> json -> LogItem
key -: value = Just (key, J.toJSON value)

(--:) :: Text -> Text -> Maybe (Text, J.Value)
(--:) = (-:)

(-?:) :: J.ToJSON json => Text -> Maybe json -> LogItem
key -?: value = (key -:) =<< value

logM :: Monad m => [LogItem] -> LogT m ()
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
              , clientKey :: OcbKey
              , clientAddress :: Maybe SockAddr
        }
  |])

$(declareLenses [d|
        data ToServer = ToServer {
                serverSocket :: Socket -- ^ connected UDP socket
              , serverKey :: OcbKey
        }
  |])


startRemoteServer :: [String] -> IO ToServer
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
        return (ToServer sock sharedEncryptionKey)
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

startLocalServer :: IO ToClient
startLocalServer = do
        key
         <- either fail return
            <=< withFile "/dev/urandom" ReadMode
            $ \h -> Data.Serialize.decode <$> B.hGet h 16
        sock <- socket AF_INET Datagram defaultProtocol
        bind sock $ SockAddrInet (PortNum 0) 0
        B.putStr . message key =<< socketPort sock
        return $ ToClient sock key Nothing
    where
        message key port = BC.unlines [
                "",
                BC.unwords [
                        "MOSH CONNECT",
                        (BC.pack . show) port,
                        (BC.takeWhile (/= '=')
                         . B64.encode
                         . Data.Serialize.encode) key],
                "",
                "This is mosh-mitm."]


relay :: ToServer -> ToClient -> LogIO ()
relay server client = join . lift . runConcurrently
        $ return () <$ Concurrently (threadDelay 1000000000 {-MICROseconds-})
          <|> onPacketFromClient
              <$> Concurrently (recvFrom (client ^. clientSocket) 4096)
          <|> onPacketFromServer
              <$> Concurrently (recv (server ^. serverSocket) 4096)
    where

        onPacketFromClient :: (ByteString, SockAddr) -> LogIO ()
        onPacketFromClient (packet, newAddress) = do
                forward "client-server" packet
                        (client ^. clientKey)
                        (server ^. serverKey)
                        (Just $ send (server ^. serverSocket))
                relay server (clientAddress .~ Just newAddress $ client)

        onPacketFromServer :: ByteString -> LogIO ()
        onPacketFromServer packet = do
                forward "server-client" packet
                        (server ^. serverKey)
                        (client ^. clientKey)
                        (flip (sendTo (client ^. clientSocket))
                         <$> (client ^. clientAddress))
                relay server client

        forward :: Text ->
                   ByteString ->
                   OcbKey ->
                   OcbKey ->
                   Maybe (ByteString -> IO Int) ->
                   LogIO ()
        forward direction bsPacketIn keyDecrypt keyEncrypt sendOn = do
                cbSent <- lift . sequence $ sendOn <*> bsPacketOut
                logM ["what" --: "relayed UDP packet",
                      "direction" --: direction,
                      "count-bytes-received" -: B.length bsPacketIn,
                      "count-bytes-sent" -?: cbSent,
                      "packet-decoding-error" -?: packetInDecodingError,
                      "nonce" -?: (fmap . view) packetNonce packetIn,
                      "fragment-decoding-error" -?: fragmentInDecodingError,
                      "fragment" -?: fragmentIn]
            where
                packetIn' = decode bsPacketIn
                packetInDecodingError = (hush . flipE) packetIn'
                packetIn = hush packetIn' :: Maybe Packet
                fragmentIn' :: Maybe (Either String Fragment)
                fragmentIn' = do
                        p <- packetIn
                        paramDecrypt <- buildOcbParams keyDecrypt
                                        $ nonceFromMoshNonce (p ^. packetNonce)
                        bs' <- ocbAesDecrypt
                                paramDecrypt
                                (p ^. packetPayload)
                        return . decode $ bs'
                fragmentInDecodingError = hush . flipE =<< fragmentIn'
                fragmentIn :: Maybe Fragment
                fragmentIn = hush =<< fragmentIn'
                packetOut :: Maybe Packet
                packetOut = do
                        nonce <- view packetNonce <$> packetIn
                        paramEncrypt
                         <- buildOcbParams keyEncrypt $ nonceFromMoshNonce nonce
                        Packet nonce . ocbAesEncrypt paramEncrypt . encode
                            <$> fragmentIn
                bsPacketOut = encode <$> packetOut


main :: IO ()
main = withSocketsDo $ do
        remoteServer <- startRemoteServer =<< getArgs
        localServer <- startLocalServer
        runDetached Nothing DevNull
            . logToFile "/home/dave/tmp/mosh-mitm.log"
            $ relay remoteServer localServer

