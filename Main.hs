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
adServer = Setting "adServer" "ldaps://example.ad.server:636"

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
ldapPath' = [OU "Global", DC "aspect", DC "com"]
ldapPath :: String
ldapPath = buildPath ldapPath'

userAttrs :: SearchAttributes
userAttrs = LDAPAttrList ["sn", "givenName", "cn", "mail", "armID", "userPrincipalName"]

findUser :: Username -> LDAP -> IO [LDAPEntry]
findUser name con = ldapSearch con (Just ldapPath) LdapScopeSubtree (Just ("(&(objectClass=User)(sn=" ++ name ++ "))")) userAttrs True

ldapPasswordChange :: Password -> LDAPMod
ldapPasswordChange pass = LDAPMod LdapModReplace "UnicodePwd" [C.unpack . encodeUtf16LE $ pack pass]

login :: LDAP -> Username -> IO ()
login con user = do 
    putStr $ "Enter current password for " ++ user ++ ": "
    pass <- readLn
    result <- try $ ldapSimpleBind con user pass
    case result of
        Right _ -> return ()
        Left (x :: SomeException) -> do
            putStrLn "Login failed, password or username wrong, try again (^c to cancel)."
            login con user

getNewPassword :: IO String
getNewPassword = do
    putStr $ "Enter new password: "
    newPass <- readLn
    putStr $ "Enter new password again: "
    newPass2 <- readLn
    if newPass /= newPass2 then do
        putStrLn "Error, passwords don't match, try again."
        getNewPassword
    else
        return newPass

changePassword :: URL -> Username -> IO ()
changePassword url user = do
    con <- ldapInitialize url
    login con user
    adUser <- findUser user con
    case adUser of 
        [] -> putStrLn $ "Unable to find a user with username of " ++ user
        (x:[]) -> do
            newPass <- getNewPassword
            ldapModify con (ledn x) [ldapPasswordChange newPass]
        (x:y:_) -> do
            putStrLn $ "Multiple users found with username of " ++ user ++ ", unable to proceed"

main :: IO ()
main = do
    (server, user) <- ldapConfig
    changePassword server user
