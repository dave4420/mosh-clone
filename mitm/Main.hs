-- async
import Control.Concurrent.Async

-- base
import Control.Applicative
import Control.Concurrent (threadDelay)
import Control.Monad
import Data.List
import System.Environment (getArgs)

-- base64-bytestring
import qualified Data.ByteString.Base64 as B64

-- bytestring
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

-- cereal
import qualified Data.Serialize

-- cipher-aes128
import Crypto.Cipher.AES128

-- daemons
import System.Posix.Daemon

-- errors
import Control.Error

-- network
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString

-- lens
import Control.Lens

-- process
import System.Process


$(declareLenses [d|
        data ToClient = ToClient {
                clientSocket :: Socket -- ^ disconnected UDP socket
              , clientAddress :: Maybe SockAddr
        }
  |])

type ToServer = Socket -- ^ connected UDP socket


startRemoteServer :: [String] -> IO (AESKey128, ToServer)
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
        parseKey :: ByteString -> Maybe AESKey128
        parseKey bs = do
                guard (B.length bs == 22)
                let key = B64.decodeLenient bs
                guard (B.length key == 16)
                buildKey key

startLocalServer :: AESKey128 -> IO ToClient
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

relay :: ToServer -> ToClient -> IO ()
relay server client = join . runConcurrently
        $ return () <$ Concurrently (threadDelay 1000000000 {-MICROseconds-})
          <|> onPacketFromClient
              <$> Concurrently (recvFrom (client ^. clientSocket) 4096)
          <|> onPacketFromServer <$> Concurrently (recv server 4096)
    where
        onPacketFromClient (packet, newAddress) = do
                _count <- send server packet
                relay server (clientAddress .~ Just newAddress $ client)
        onPacketFromServer packet = do
                _count
                 <- maybe (return 0) (sendTo (client ^. clientSocket) packet)
                    $ client ^. clientAddress
                relay server client

main :: IO ()
main = withSocketsDo $ do
        (key, remoteServer) <- startRemoteServer =<< getArgs
        localServer <- startLocalServer key
        runDetached Nothing DevNull $ relay remoteServer localServer

