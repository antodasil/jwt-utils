<?php

namespace JWTUtils;

class JWTSigner
{

    private static JWTSigner $instance = null;

    protected string $jwtAlgo;
    protected string $secretKey;
    
    protected const SUPPORTED_ALGORITHMS = array(
        'HS256' => array('sha256', 'hmac'),
        'HS384' => array('sha384', 'hmac'),
        'HS512' => array('sha512', 'hmac'),
        'RS256' => array('sha256', 'rsa'),
        'RS384' => array('sha384', 'rsa'),
        'RS512' => array('sha512', 'rsa')
    );

    private function __construct()
    {
        $this->jwtAlgo = JWTConstants::HEADER_ALGORITHM_DEFAULT;
        $this->secretKey = JWTConstants::SECRET_KEY_DEFAULT;
    }

    public static function getInstance()
    {
        if(is_null(self::$instance))
        {
            self::$instance = new JWTSigner();
        }
        return self::$instance;
    }

    /**
     * Init JWT variables (secret key and jwt algorithm)
     * 
     * @param string $jwtAlgo
     * @param string|resource $secretKey
     */
    public function init($secretKey, string $jwtAlgo = JWTConstants::HEADER_ALGORITHM_DEFAULT): void
    {
        $this->jwtAlgo = $jwtAlgo;
        $this->secretKey = $secretKey;
    }

    /**
     * Return signature from header and payload
     * 
     * @param JWTArray $header
     * @param JWTArray $payload
     * 
     * @return string
     * 
     * @throws JWTException
     */
    public function sign(JWTArray $header, JWTArray $payload): string
    {

        if(is_null($this->jwtAlgo) || !array_key_exists($this->jwtAlgo, self::SUPPORTED_ALGORITHMS))
        {
            throw new JWTException('JWTAlgo is missing in config file or not supported');
        }
        if(is_null($this->secretKey) || is_null($this->jwtAlgo))
        {
            throw new JWTException('Secret key ir JwtAlgo is missing');
        }

        $concatenated = $header->encode() + '.' + $payload->encode();
        list($hashAlgo, $typeAlgo) = self::SUPPORTED_ALGORITHMS[$this->jwtAlgo];

        switch($typeAlgo)
        {
            case 'hmac':
                $secretKey = $this->secretKey;
                return JWTUtils::base64UriEncode(hash_hmac($hashAlgo, $concatenated, $secretKey, true));
            case 'rsa':
                $signature = '';
                $res = openssl_sign($concatenated, $signature, $this->secretKey, $hashAlgo);
                if(!$res)
                {
                    throw new JWTException('RSA signing key failed');
                }
                return JWTUtils::base64UriEncode($signature);
                break;
        }

        throw new JWTException('Not supported hash algorithm');
    }

}
