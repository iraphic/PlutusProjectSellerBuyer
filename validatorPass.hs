-- A security based sales system, between buyers and sellers. The seller must enter the password and use its hash, there is a script for the password validator, to lock a certain amount of funds (sales service fee) in the pay-to-script transaction output.
-- The buyer must enter the same password as the seller, by entering the transaction output. If the password is correct, the validator script can issue funds for its services. Otherwise, the funds remain locked.

import Control.Monad (void)
import Data.ByteString.Char8 qualified as C
import Data.Map (Map)
import Data.Map qualified as Map
import Data.Maybe (catMaybes)
import Ledger (Address, Datum (Datum), ScriptContext, Validator, Value)
import Ledger qualified
import Ledger.Ada qualified as Ada
import Ledger.Constraints qualified as Constraints
import Ledger.Tx (ChainIndexTxOut (..))
import Ledger.Typed.Scripts qualified as Scripts
import Playground.Contract
import Plutus.Contract
import PlutusTx qualified
import PlutusTx.Prelude hiding (pure, (<$>))
import Prelude qualified as Haskell

------------------------------------------------------------

newtype HashedString = HashedString BuiltinByteString deriving newtype (PlutusTx.ToData, PlutusTx.FromData, PlutusTx.UnsafeFromData)

PlutusTx.makeLift ''HashedString

newtype ClearString = ClearString BuiltinByteString deriving newtype (PlutusTx.ToData, PlutusTx.FromData, PlutusTx.UnsafeFromData)

PlutusTx.makeLift ''ClearString

type PassSchema =
        Endpoint "passwordBenar" LockParams
        .\/ Endpoint "inputanPassword" GuessParams

data Pass
instance Scripts.ValidatorTypes Pass where
    type instance RedeemerType Pass = ClearString
    type instance DatumType Pass = HashedString

passInstance :: Scripts.TypedValidator Pass
passInstance = Scripts.mkTypedValidator @Pass
    $$(PlutusTx.compile [|| validateGuess ||])
    $$(PlutusTx.compile [|| wrap ||]) where
        wrap = Scripts.wrapValidator @HashedString @ClearString


hashString :: Haskell.String -> HashedString
hashString = HashedString . sha2_256 . toBuiltin . C.pack

clearString :: Haskell.String -> ClearString
clearString = ClearString . toBuiltin . C.pack

validateGuess :: HashedString -> ClearString -> ScriptContext -> Bool
validateGuess hs cs _ = isGoodGuess hs cs

isGoodGuess :: HashedString -> ClearString -> Bool
isGoodGuess (HashedString actual) (ClearString guess') = actual == sha2_256 guess'

passValidator :: Validator
passValidator = Scripts.validatorScript passInstance

passAddress :: Address
passAddress = Ledger.scriptAddress passValidator

data LockParams = LockParams
    { kataRahasia :: Haskell.String
    , amount     :: Value
    }
    deriving stock (Haskell.Eq, Haskell.Show, Generic)
    deriving anyclass (FromJSON, ToJSON, ToSchema, ToArgument)

newtype GuessParams = GuessParams
    { kataTebakan :: Haskell.String
    }
    deriving stock (Haskell.Eq, Haskell.Show, Generic)
    deriving anyclass (FromJSON, ToJSON, ToSchema, ToArgument)

lock :: AsContractError e => Promise () PassSchema e ()
lock = endpoint @"passwordBenar" @LockParams $ \(LockParams secret amt) -> do
    logInfo @Haskell.String $ "Bayar " <> Haskell.show amt <> " ke skrip"
    let tx         = Constraints.mustPayToTheScript (hashString secret) amt
    void (submitTxConstraints passInstance tx)

guess :: AsContractError e => Promise () PassSchema e ()
guess = endpoint @"inputanPassword" @GuessParams $ \(GuessParams theGuess) -> do
    
    logInfo @Haskell.String "Menunggu skrip memiliki UTxO minimal 1 lovelace"
    utxos <- fundsAtAddressGeq passAddress (Ada.lovelaceValueOf 1)

    let redeemer = clearString theGuess
        tx       = collectFromScript utxos redeemer

    
    let hashedSecretWord = findSecretWordValue utxos
        isCorrectSecretWord = fmap (`isGoodGuess` redeemer) hashedSecretWord == Just True
    if isCorrectSecretWord
        then logWarn @Haskell.String "Password benar! Mengirimkan transaksi"
        else logWarn @Haskell.String "Password salah! Tapi tetap mengirimkan transaksi"

    logInfo @Haskell.String "Mengirimkan transaksi untuk inputan password"
    void (submitTxConstraintsSpending passInstance utxos tx)


findSecretWordValue :: Map TxOutRef ChainIndexTxOut -> Maybe HashedString
findSecretWordValue =
  listToMaybe . catMaybes . Map.elems . Map.map secretWordValue

secretWordValue :: ChainIndexTxOut -> Maybe HashedString
secretWordValue o = do
  Datum d <- either (const Nothing) Just (_ciTxOutDatum o)
  PlutusTx.fromBuiltinData d

pass :: AsContractError e => Contract () PassSchema e ()
pass = do
    logInfo @Haskell.String "Menunggu titik akhir inputan password ..."
    selectList [lock, guess]

{- Note [Contract end point]

Contract endpoints are functions that use the wallet API to interact with password chain True. We can look at the end point of the contract from two different points of view.

1. Contract user

The contract endpoint is the visible contract interface. They provide UI (HTML form) to enter the parameters of the actions we may take as part of the contract.

2. Contract writer

As contract authors, we define an endpoint as a function that returns a value type 'MockWallet()'. This type indicates that the function uses the wallet API to produce and spend transaction output on the blockchain.

Endpoints can have any number of parameters: 'passwordBenar' has two parameters, 'inputanPassword' has one and 'startPass' has none. For each of our endpoints
include a call to 'mkFunction' at the end of the contract definition. This causes the Haskell compiler to generate a schema for the endpoint.

-}

endpoints :: AsContractError e => Contract () PassSchema e ()
endpoints = pass

mkSchemaDefinitions ''PassSchema

$(mkKnownCurrencies [])
