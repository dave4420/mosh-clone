import Mosh

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

arbitraryByteStringMinimumLength :: Int -> Gen ByteString
arbitraryByteStringMinimumLength c
        = mappend
          <$> (B.pack <$> replicateM c arbitrary)
          <*> arbitraryByteString

arbitraryByteStringMaximumLength :: Int -> Gen ByteString
arbitraryByteStringMaximumLength c = B.take c <$> arbitraryByteString


prop_packetEncodingRoundTrip :: Property
prop_packetEncodingRoundTrip = forAll (arbitraryByteStringMinimumLength 8)
        $ \bs -> Right bs === fmap encode (decode bs :: Either String Packet)

prop_packetDecodingTooShort :: Property
prop_packetDecodingTooShort = forAll (arbitraryByteStringMaximumLength 7)
        $ \bs -> isLeft (decode bs :: Either String Packet)
