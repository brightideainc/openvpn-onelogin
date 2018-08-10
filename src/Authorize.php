<?php

namespace OneVPN;

use OneVPN\Libraries\OneLogin\ApiConnector;
use OneVPN\Libraries\OneLogin\Exceptions\{ApiException, AuthorizationException};

/**
 * Undocumented class
 */
class Authorize {
    /**
     * 
     */
    public const MFA_AUTH_REQUIRED = true;

    /**
     * Undocumented variable
     *
     * @var [type]
     */
    protected static $authArgs;

    /**
     * Undocumented function
     *
     * @param array $args
     */
    public function __construct(array $args = []) {
        try {
            $this->parseAuthArgs($args);

            (new ApiConnector)->login(self::$authArgs->getUsername(), self::$authArgs->getPassword());
            exit(0);
        } catch (AuthorizationException | ApiException $e) {
            error_log('auth exception');
            error_log($e->getMessage());
            exit(1);
        }
    }

    /**
     * Undocumented function
     *
     * @param array $args
     * @return void
     * @throws AuthorizationException
     */
    private function validateArgs(array $args = []) : void {
        if (!isset($args[1]) || !file_exists($args[1])) {
            throw new AuthorizationException("Invalid Arguments Provided");
        }
    }

    /**
     * Undocumented function
     *
     * @return void
     */
    public static function getAuthArgs() {
        return self::$authArgs;
    }

    /**
     * Undocumented function
     *
     * @param array $args
     * @return void
     * @throws AuthorizationException
     */
    private function parseAuthArgs(array $args) : void {
        try {
            $authArgs = [
                getenv('username') ?? false,
                getenv('password') ?? false
            ];
            
            if ($authArgs[0] === false && $authArgs[1] === false) {
                $authArgs = file($args[1], FILE_IGNORE_NEW_LINES);
            }
        } catch (\Exception $e) {
            throw AuthorizationException($e->getMessage());
        }

        if (count($authArgs) <> 2) {
            throw new AuthorizationException("Unable to load login credentials from OpenVPN");
        }

        if($staticChallenge = $this->parseStaticChallengePassword($authArgs)) {
            $authArgs[1] = $staticChallenge[0];
            $this->setAuthArgs($authArgs, null, $staticChallenge[1]);
        } else if (self::MFA_AUTH_REQUIRED === true) {
            if (preg_match('/(\-[0-9]+)$/', $authArgs[1], $matches)) {
                $this->setAuthArgs($authArgs, $matches);
            } else {
                throw new AuthorizationException("No MFA Token Provided");
            }
        } else {
            $this->setAuthArgs($authArgs, null);
        }
    }

    private function parseStaticChallengePassword(array $authArgs) : ?array {
        $password = explode(':', $authArgs[1]);
        if($password[0] !== 'SCRV1' ) {
            return null;
        }

        return [base64_decode($password[1]), base64_decode($password[2])];
    }

    /**
     * Undocumented function
     *
     * @param array $authArgs
     * @param array|null $matches
     * @param string|null $mfa
     * @return void
     */
    private function setAuthArgs(array $authArgs, ?array $matches = null, ?string $mfa = null) : void {
        self::$authArgs = new class($authArgs, $matches, $mfa) {
            protected $username = null;
            protected $password = null;
            protected $mfaCode = null;

            function __construct(array $authArgs, ?array $matches = null, ?string $mfa = null) {
                $this->username = $authArgs[0];

                if ($matches) {
                    $this->password = str_replace($matches[0], '', $authArgs[1]);
                    $this->mfaCode = ltrim($matches[0], '-');
                } else {
                    $this->password = $authArgs[1];
                }

                if($mfa) {
                    $this->mfaCode = $mfa;
                }
            }

            public function getUsername() : string {
                return $this->username;
            }
            public function getPassword() : string {
                return $this->password;
            }
            public function getMFACode() : ?string {
                return $this->mfaCode;
            }
        };
    }
}
