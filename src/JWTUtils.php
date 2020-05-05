<?php

namespace JWTUtils;

/**
 * class JWTUtils
 * 
 * JWT methods
 */
class JWTUtils {

    protected static string $jwtAlgo = 'HS256';
    protected static $secretKey = 'mustBeModified';
    
    protected const SUPPORTED_ALGORITHMS = array(
        'HS256' => array('sha256', 'hmac'),
        'HS384' => array('sha384', 'hmac'),
        'HS512' => array('sha512', 'hmac'),
        'RS256' => array('sha256', 'rsa'),
        'RS384' => array('sha384', 'rsa'),
        'RS512' => array('sha512', 'rsa')
    );

    /**
     * Set JWT variables (secret key and jwt algorithm)
     * 
     * @param string $jwtAlgo
     * @param string|resource $secretKey
     */
    public static function setVariables($secretKey, string $jwtAlgo = 'HS256'): void {
        self::$jwtAlgo = $jwtAlgo;
        self::$secretKey = $secretKey;
    }

    /**
     * Return base64url encoded string
     * 
     * @param string $string
     * 
     * @return string
     */
    public static function base64UriEncode(string $string): string {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }

    /**
     * Decode base64url string
     * 
     * @param string $string
     * 
     * @return string
     */
    public static function base64UriDecode(string $string): string {
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $string));
    }

    /**
     * Return true if the string is a JWT token
     * 
     * @param string $token
     * 
     * @return bool
     */
    public static function isJWT(string $token): bool {
        return preg_match("^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_=]+$", $token) === 1;
    }

    /**
     * Return signature from header and payload
     * 
     * @param array $header
     * @param array $payload
     * 
     * @return string
     * 
     * @throws JWTException
     */
    public static function sign(array $header, array $payload): string {

        $algo = self::$jwtAlgo;
        if(is_null($algo) || !array_key_exists($algo, self::SUPPORTED_ALGORITHMS)) {
            throw new JWTException('JWTAlgo is missing in config file or not supported');
        }
        if(is_null(self::$secretKey) || is_null(self::$jwtAlgo)) {
            throw new JWTException('Secret key ir JwtAlgo is missing');
        }
        $header  = self::base64UriEncode(json_encode($header));
        $payload = self::base64UriEncode(json_encode($payload));

        list($hashAlgo, $typeAlgo) = self::SUPPORTED_ALGORITHMS[$algo];
        $concatenated = "$header.$payload";

        switch($typeAlgo) {
            case 'hmac':
                $secretKey = self::$secretKey;
                return self::base64UriEncode(hash_hmac($hashAlgo, $concatenated, $secretKey, true));
            case 'rsa':
                $signature = '';
                $res = openssl_sign($concatenated, $signature, self::$secretKey, $hashAlgo);
                if(!$res) {
                    throw new JWTException('RSA signing key failed');
                }
                return self::base64UriEncode($signature);
                break;
        }

        throw new JWTException('Not supported hash algorithm');
    }

}
