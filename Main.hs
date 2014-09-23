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
import System.IO (hFlush, stdin, hSetEcho, stdout, hGetLine, hSetBuffering, BufferMode (..), hPutStr, hPutStrLn)
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
userAttrs = LDAPAttrList ["sn", "givenName", "cn", "mail", "userPrincipalName"]

stripDomain :: Username -> Username
stripDomain name = takeWhile (/= '@') name

findUser :: Username -> LDAP -> IO [LDAPEntry]
findUser name con = ldapSearch con (Just ldapPath) LdapScopeSubtree (Just ("(&(objectClass=User)(userPrincipalName=" 
    ++ name ++ "))")) LDAPAllUserAttrs False

ldapPasswordChange :: Password -> [LDAPMod]
ldapPasswordChange pass =
    [ LDAPMod LdapModDelete "unicodePwd" []
    , LDAPMod LdapModAdd "unicodePwd" [C.unpack . encodeUtf16LE $ pack pass]
    ]

login :: LDAP -> Username -> IO ()
login con user = do 
    pass <- secureRead $ "Enter current password for " ++ user ++ ": "
    catchLDAP (ldapSimpleBind con user pass) $ \x -> do
        putStrLn $ "Login failed: " ++ show x
        putStrLn "Try again (^c to cancel)."
        login con user

secureRead :: String -> IO String
secureRead prompt = do
    hSetBuffering stdout NoBuffering
    hPutStr stdout prompt
    hFlush stdout
    hSetEcho stdin False
    line <- getLine
    hPutStrLn stdout ""
    hSetEcho stdin True
    hSetBuffering stdout LineBuffering
    return line

getNewPassword :: IO String
getNewPassword = do
    newPass <- secureRead "Enter new password: "
    newPass2 <- secureRead "Enter new password again: "
    if newPass /= newPass2 then do
        hPutStrLn stdout "Error, passwords don't match, try again."
        getNewPassword
    else
        return newPass

setNewPassword :: LDAP -> String -> IO ()
setNewPassword con dc = do
    newPass <- getNewPassword
    catchLDAP (ldapModify con dc (ldapPasswordChange ("\"" ++ newPass ++ "\""))) $ \x -> do
        case code x of
            LdapConstraintViolation -> putStrLn "Password does not meet complexity requirements, try again." >> setNewPassword con dc
            _ -> putStrLn $ "Unknown error occured: " ++ show x

changePassword :: URL -> Username -> IO ()
changePassword url user = do
    con <- ldapInitialize url
    login con user
    adUser <- findUser user con
    case adUser of 
        [] -> putStrLn $ "Unable to find a user with username of " ++ user
        (x:[]) -> setNewPassword con (ledn x)
        (x:y:_) -> putStrLn $ "Multiple users found with username of " ++ user ++ ", unable to proceed"

main :: IO ()
main = do
    (server, user) <- ldapConfig
    changePassword server user
