<?php

namespace JWTUtils;

/**
 * class JWTUtils
 * 
 * JWT methods
 */
class JWTUtils
{

    /**
     * Return base64url encoded string
     * 
     * @param string $string
     * 
     * @return string
     */
    public static function base64UriEncode(string $string): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }

    /**
     * Decode base64url string
     * 
     * @param string $string
     * 
     * @return string
     */
    public static function base64UriDecode(string $string): string
    {
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $string));
    }

    /**
     * Return true if the string is a JWT token
     * 
     * @param string $token
     * 
     * @return bool
     */
    public static function isJWT(string $token): bool
    {
        return preg_match("^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_=]+$", $token) === 1;
    }

}
