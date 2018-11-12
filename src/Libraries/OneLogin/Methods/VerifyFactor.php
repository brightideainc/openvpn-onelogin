<?php

namespace OneVPN\Libraries\OneLogin\Methods;

use GuzzleHttp\Client;
use OneVPN\Libraries\Config;
use OneVPN\Libraries\OneLogin\Interfaces\Method;
use OneVPN\Libraries\OneLogin\Response;
use OneVPN\Libraries\OneLogin\Exceptions\ApiException;

/**
 * Undocumented class
 */
class VerifyFactor implements Method {
    /**
     * 
     */
    protected const ENDPOINT_URL = 'https://api.us.onelogin.com/api/1/saml_assertion/verify_factor';

    /**
     * Undocumented function
     *
     * @param string $apiToken
     * @param [type] $deviceId
     * @param [type] $stateToken
     * @param [type] $otpToken
     * @return array|bool|void
     */
    public static function request(string $apiToken = null, $deviceId = null, $stateToken = null, $otpToken = null) {
        return self::handle(Response::fromGuzzle((new Client)->request('POST', self::ENDPOINT_URL, [
            'headers' => [
                'content-type' => 'application/json',
                'authorization' => "bearer:{$apiToken}"
            ],
            'json' => [
                'device_id' => (string) $deviceId,
                'state_token' => (string) $stateToken,
                'otp_token' => (string) $otpToken,
                'app_id' => Config::getOpt('app_id')
            ],
            'http_errors' => false
        ])));
    }

    /**
     * Undocumented function
     *
     * @param Response $response
     * @return array|bool
     */
    public static function handle(Response $response) {        
        switch ($response->getStatusCode()) {
            case 200:
                return $response->getJson()->status->message === 'Success';
            default:
                return ['message' => $response->getJson()->status->message, 'statusCode' =>  $response->getStatusCode()];
        }
    }
}
