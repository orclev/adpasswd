{-# LANGUAGE RankNTypes, ScopedTypeVariables, OverloadedStrings #-}
module Main where

import Data.AppSettings
import System.PosixCompat.User hiding (userName)
import System.PosixCompat.Files
import Control.Exception
import LDAP
import Data.List (intersperse, concat)
import Data.Text (pack)
import Data.Text.Encoding (encodeUtf16LE)
import qualified Data.ByteString.Char8 as C

data PathPiece = OU String | DC String | SN String

type Username = String
type Password = String
type URL = String

buildPath :: [PathPiece] -> String
buildPath = concat . intersperse "," . map bp
  where
    bp (OU x) = "ou="++x
    bp (DC x) = "DC="++x
    bp (SN x) = "sn="++x

adServer :: Setting URL
adServer = Setting "adServer" "ldaps://10.3.88.97:636"

userName :: Username -> Setting Username
userName name = Setting "username" name

defaultConfig :: IO DefaultConfig
defaultConfig = do
    name <- getLoginName
    return $ getDefaultConfig $ do
        setting adServer
        setting $ userName name

configLocation :: IO FilePath
configLocation = do
    name <- getLoginName
    user <- getUserEntryForName name
    return $ (homeDirectory user) ++ "/.adpasswd"

getConfig :: forall a. Read a => IO (Setting a -> a)
getConfig = do
    p <- configLocation
    readResult <- try $ readSettings (Path p)
    case readResult of
        Right (conf, GetSetting getSetting) -> do
            defConfig <- defaultConfig
            saveSettings defConfig (Path p) conf
            return getSetting
        Left (x :: SomeException) -> error "Error reading the config file!"

ldapConfig :: IO (URL, Username)
ldapConfig = do
    getSetting <- getConfig
    name <- getLoginName
    let server = getSetting adServer
        user = getSetting $ userName name
    return (server, user)

ldapPath' :: [PathPiece]
ldapPath' = [OU "tenant", OU "WFM", DC "wfm", DC "cto", DC "voxeo", DC "net"]
ldapPath :: String
ldapPath = buildPath ldapPath'

userAttrs = LDAPAttrList ["sn", "givenName", "cn", "mail", "armID", "userPrincipalName"]

ldapPasswordChange :: Password -> LDAPMod
ldapPasswordChange pass = LDAPMod LdapModReplace "UnicodePwd" [C.unpack . encodeUtf16LE $ pack pass]

userDn :: String -> String
userDn name = buildPath [SN name, OU "Global",DC "aspect",DC "com"]

changePassword :: URL -> Username -> IO ()
changePassword url user = do
    con <- ldapInitialize url
    putStr $ "Enter current password for " ++ user ++ ": "
    oldPass <- readStrLn
    putStr $ "Enter new password: "
    newPass <- readStrLn
    ldapSimpleBind con user oldPass
    ldapModify con (userDn user) [ldapPasswordChange newPass]


main :: IO ()
main = do
    (server, user) <- ldapConfig
    changePassword server user
