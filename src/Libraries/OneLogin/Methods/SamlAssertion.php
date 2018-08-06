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
class SamlAssertion implements Method {
    /**
     * 
     */
    protected const ENDPOINT_URL = 'https://api.us.onelogin.com/api/1/saml_assertion';

    /**
     * Undocumented variable
     *
     * @var [type]
     */
    protected static $apiToken;

    /**
     * Undocumented function
     *
     * @param string $apiToken
     * @param string $username
     * @param string $password
     * @return void
     */
    public static function request(string $apiToken = null, string $username = null, string $password=  null) {
        self::$apiToken = $apiToken;

        return (Response::fromGuzzle((new Client)->request('POST', self::ENDPOINT_URL, [
            'headers' => [
                'content-type' => 'application/json',
                'authorization' => "bearer:{$apiToken}"
            ],
            'json' => [
                'username_or_email' => $username,
                'password' => $password,
                'app_id' => Config::getOpt('app_id'),
                'subdomain' => Config::getOpt('subdomain')
            ],
            'http_errors' => false
        ])));
    }

    /**
     * Undocumented function
     *
     * @param Response $response
     * @return void
     */
    public static function handle(Response $response) {
        switch ($response->getStatusCode()) {
            case 200:
                switch ($response->getJson()->status->message) {
                    case 'Success' :
                    case 'MFA is required for this user' :
                        try {
                            $userRoles = Users::getRoles(self::$apiToken, $response->getJson()->data[0]->user->id)->data[0];
                            if (in_array(Config::getOpt('onelogin_role_id'), $userRoles)) {
                                if ($response->getJson()->status->message === 'Success') {
                                    return true;
                                }

                                $responseData = $response->getJson()->data[0];
                                if (\OneVPN\Authorize::MFA_AUTH_REQUIRED === true) {
                                    return VerifyFactor::request(self::$apiToken, $responseData->devices[0]->device_id, $responseData->state_token, \OneVPN\Authorize::getAuthArgs()->getMFACode());
                                } else {
                                    return true;
                                }
                            } else {
                                throw new ApiException('User does not have valid OneLogin VPN Role');
                                return false;
                            }
                        } catch (\Exception $e) {
                            throw new ApiException($e->getMessage());
                        }


                    break;
                }
            default:
                throw new ApiException($response->getJson()->status->message, $response->getStatusCode());
        }
    }
}
