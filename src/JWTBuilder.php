<?php

namespace JWTUtils;

class JWTBuilder {

    protected array $header;
    protected array $payload;

    public function __construct() {
        $this->header  = array();
        $this->payload = array();
    }

    /**
     * Get header
     * 
     * @return array
     */
    public function getHeader(): array {
        return $this->header;
    }

    /**
     * Get payload
     * 
     * @return array
     */
    public function getPayload(): array {
        return $this->payload;
    }

    /**
     * Get JWTToken from token string
     * 
     * @param string $token
     * 
     * @return JWTToken|null
     */
    public static function get(string $token): ?JWTToken {
        
        if(!JWTUtils::isJWT($token)) {
            return null;
        }

        list($header, $payload, $signature) = explode('.', $token);
        $header  = json_decode(JWTUtils::base64UriDecode($header));
        $payload = json_decode(JWTUtils::base64UriDecode($payload));
        return new JWTToken($header, $payload, $signature);
    }

    /**
     * Build JWTToken
     * 
     * @return JWTToken
     */
    public function buildToken(): JWTToken {
        if(!array_key_exists('alg', $this->getHeader())) {
            $this->setAlgorithm('HS256');
        }
        if(!array_key_exists('typ', $this->getHeader())) {
            $this->setType('JWT');
        }

        return new JWTToken($this->getHeader(), $this->getPayload());
    }

    /**
     * Add an header claim
     * 
     * @param string $key
     * @param string $value
     * 
     * @return JWTBuilder
     */
    public function setHeader(string $key, string $value): JWTBuilder {
        $this->header[$key] = $value;
        return $this;
    }

    /**
     * Set signature algorithm
     * 
     * @param string $algorithm
     * 
     * @return JWTBuilder
     */
    public function setAlgorithm(string $algorithm): JWTBuilder {
        $this->setHeader('alg', $algorithm);
        return $this;
    }

    /**
     * Set token type
     * 
     * @param string $type
     * 
     * @return JWTBuilder
     */
    public function setType(string $type = 'JWT'): JWTBuilder {
        $this->setHeader('typ', $type);
        return $this;
    }

    /**
     * Add a payload claim
     * 
     * @param string $key
     * @param string $value
     * 
     * @return JWTBuilder
     */
    public function set(string $key, string $value): JWTBuilder {
        $this->payload[$key] = $value;
        return $this;
    }

    /**
     * Set issuer claim
     * 
     * @param string $issuer
     * 
     * @return JWTBuilder
     */
    public function setIssuer(string $issuer): JWTBuilder {
        return $this->set('iss', $issuer);
    }

    /**
     * Set subject claim
     * 
     * @param string $subject
     * 
     * @return JWTBuilder
     */
    public function setSubject(string $subject): JWTBuilder {
        return $this->set('sub', $subject);
    }

    /**
     * Set audience claim
     * 
     * @param string $audience
     * 
     * @return JWTBuilder
     */
    public function setAudience(string $audience): JWTBuilder {
        return $this->set('aud', $audience);
    }

    /**
     * Set expiration time claim
     * 
     * @param string $expirationTime
     * 
     * @return JWTBuilder
     */
    public function setExpirationTime(string $expirationTime): JWTBuilder {
        return $this->set('exp', $expirationTime);
    }

    /**
     * Set not before claim
     * 
     * @param string $notBefore
     * 
     * @return JWTBuilder
     */
    public function setNotBefore(string $notBefore): JWTBuilder {
        return $this->set('nbf', $notBefore);
    }

    /**
     * Set issued at claim
     * 
     * @param string $issuedAt
     * 
     * @return JWTBuilder
     */
    public function setIssuedAt(string $issuedAt): JWTBuilder {
        return $this->set('iat', $issuedAt);
    }

    /**
     * Set jwt ID claim
     * 
     * @param string $jwtID
     * 
     * @return JWTBuilder
     */
    public function setJwtID(string $jwtID): JWTBuilder {
        return $this->set('jti', $jwtID);
    }
}