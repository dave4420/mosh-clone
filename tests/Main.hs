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

prop_tautology :: Property
prop_tautology = property True
