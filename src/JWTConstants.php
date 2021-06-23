<?php

namespace JWTUtils;

class JWTConstants
{

    const HEADER_ALGORITHM = 'alg';
    const HEADER_TYPE = 'typ';

    const PAYLOAD_ISSUER = 'iss';
    const PAYLOAD_SUBJECT = 'sub';
    const PAYLOAD_AUDIENCE = 'aud';
    const PAYLOAD_EXPIRATION_TIME = 'exp';
    const PAYLOAD_NOT_BEFORE = 'nbf';
    const PAYLOAD_ISSUED_AT = 'iat';
    const PAYLOAD_ID = 'jti';

    const HEADER_TYPE_DEFAULT = 'JWT';
    const HEADER_ALGORITHM_DEFAULT = 'HS256';
    const SECRET_KEY_DEFAULT = 'mustBeModified';
}
