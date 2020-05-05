<?php

namespace JWTUtils;

use DateTime;

class JWTToken {
    protected array    $header;
    protected array    $payload;
    protected string   $signature;
    protected JWTUtils $utils;

    /**
     * JWTToken __construct
     * 
     * @param array       $header
     * @param array       $payload
     * @param string|null $signature
     * 
     * @return JWTToken
     */
    public function __construct(array $header, array $payload, ?string $signature = null) {
        $this->header    = $header;
        $this->payload   = $payload;
        $this->signature = $signature ?? JWTUtils::sign($header, $payload);
    }

    /**
     * Get the value of header
     *
     * @return array
     */
    public function getHeader():array {
        return $this->header;
    }

    /**
     * Get the value of payload
     *
     * @return array
     */
    public function getPayload(): array {
        return $this->payload;
    }

    /**
     * Get the value of signature
     *
     * @return string
     */
    public function getSignature(): string {
        return $this->signature;
    }

    /**
     * Get the string token
     * 
     * @return string
     */
    public function getToken(): string {
        $header  = JWTUtils::base64UriEncode(json_encode($this->getHeader()));
        $payload = JWTUtils::base64UriEncode(json_encode($this->getPayload()));
        $signature = $this->getSignature();
        return "$header.$payload.$signature";
    }

    /**
     * Return true if the token is valid
     * => Check iat, exp, nbf values and signature
     * 
     * @return bool
     */
    public function isValid(): bool {

        if(array_key_exists('iat', $this->getPayload()) && $this->getPayload()['iat'] !== null) {
            $dateToken = new DateTime();
            $dateToken->setTimestamp((int) $this->getPayload()['iat']);
            
            if($dateToken > new Datetime()) {
                return false;
            }
        }
        
        if(array_key_exists('exp', $this->getPayload()) && $this->getPayload()['exp'] !== null) {
            $dateExp = new DateTime();
            $dateExp->setTimestamp((int) $this->getPayload()['exp']);
            
            if($dateExp < new Datetime()) {
                return false;
            }
        }

        if(array_key_exists('nbf', $this->getPayload()) && $this->getPayload()['nbf'] !== null) {
            $dateBegin = new Datetime();
            $dateBegin->setTimestamp((int) $this->getPayload()['nbf']);

            if($dateBegin > new Datetime()) {
                return false;
            }
        }

        return hash_equals($this->getSignature(), JWTUtils::sign($this->getHeader(), $this->getPayload()));
    }

    /**
     * Check if the payload[$key] value and $value are equals
     * 
     * @param string $key
     * @param string $value
     * 
     * @return bool
     */
    public function check(string $key, string $value): bool {

        if(!array_key_exists($key, $this->getPayload()) || is_null($this->getPayload()[$key])) {
            return false;
        }
        return $this->getPayload()[$key] === $value;
    }

    /**
     * Return true if token is issued by given value
     * 
     * @param string $issuer
     * 
     * @return bool
     */
    public function checkIssuer(string $issuer): bool {
        return $this->check('iss', $issuer);
    }

    /**
     * Return true if token is related for given value
     * 
     * @param string $subject
     * 
     * @return bool
     */
    public function checkSubject(string $subject): bool {
        return $this->check('sub', $subject);
    }

    /**
     * Return true if token is permitted for given value
     * 
     * @param string $audience
     * 
     * @return bool
     */
    public function checkAudience(string $audience): bool {
        return $this->check('aud', $audience);
    }

    /**
     * Return true if token is identified by given value
     * 
     * @param string $jwtID
     * 
     * @return bool
     */
    public function checkJwtID(string $jwtID): bool {
        return $this->check('jti', $jwtID);
    }

    /**
     * Check all standard claim values
     * 
     * @param string|null $issuer
     * @param string|null $subject
     * @param string|null $audience
     * @param string|null $jwtID
     * 
     * @return bool
     */
    public function checkAll(?string $issuer = null, ?string $subject = null, ?string $audience = null, ?string $jwtID = null): bool {
        return (is_null($issuer)   ? true : $this->checkIssuer($issuer))
            && (is_null($subject)  ? true : $this->checkSubject($subject))
            && (is_null($audience) ? true : $this->checkAudience($audience))
            && (is_null($jwtID)    ? true : $this->checkJwtID($jwtID));
    }

    /**
     * __toString method
     * 
     * @return string
     */
    public function __toString(): string {
        return $this->getToken();
    }

}