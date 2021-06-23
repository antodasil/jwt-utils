<?php

namespace JWTUtils;

class JWTArray
{
    protected array $array;


    public function __construct()
    {
        $this->array = array();
    }

    public function setArray(array $array): void
    {
        $this->array = $array;
    }

    /**
     * Get a claim
     * 
     * @param string $key
     * @return String $value
     */
    public function get(string $key): string
    {
        return $this->array[$key];
    }

    /**
     * Set a claim
     * 
     * @param string $key
     * @param string $value
     * @return JWTArray
     */
    public function set(string $key, string $value): void
    {
        $this->array[$key] = $value;
    }

    /**
     * Return true is $key exist in array
     * 
     * @param string $key
     * @return bool
     */
    public function exist(string $key): bool
    {
        return array_key_exists($key, $this->array) && $this->array[$key] !== null;
    }

    /**
     * Encode the array
     * @return String
     */
    public function encode(): string
    {
        return JWTUtils::base64UriEncode(json_encode($this->array));
    }

    /**
     * Decode a string to a JWTArray
     */
    public static function decode(string $string): JWTArray {
        $jwtArray = new JWTArray();
        $jwtArray->setArray(json_decode(JWTUtils::base64UriDecode($string)));
        return $jwtArray;
    }
}
