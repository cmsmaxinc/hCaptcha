<?php

namespace Scyllaly\HCaptcha;

use Symfony\Component\HttpFoundation\Request;
use GuzzleHttp\Client;

class HCaptcha
{
    const CLIENT_API = 'https://hcaptcha.com/1/api.js';
    const VERIFY_URL = 'https://hcaptcha.com/siteverify';

    /**
     * The hCaptcha secret key.
     */
    protected string $secret;

    /**
     * The hCaptcha sitekey key.
     */
    protected string $sitekey;

    /**
     * The HTTP client used to send requests.
     */
    protected \GuzzleHttp\Client $http;

    /**
     * The cached verified responses.
     */
    protected array $verifiedResponses = [];

    /**
     * lastScore
     */
    protected ?float $lastScore = null;

    /**
     * Whether to use hCaptcha or not.
     */
    protected bool $enabled;

    /**
     * Cache of response verifications with timestamps
     * @var array
     */
    protected array $responseCache = [];

    /**
     * Cache duration in seconds
     */
    protected int $cacheDuration = 120;


    /**
     * HCaptcha constructor.
     */
    public function __construct(string $secret, string $sitekey, array $options = [], bool $enabled = true)
    {
        $this->secret = $secret;
        $this->sitekey = $sitekey;
        $this->http = new Client($options);
        $this->enabled = $enabled;
    }

    /**
     * Get the hCaptcha verification details for a given response
     */
    public function getResponseDetails(string $response, ?string $clientIp = null): array
    {
        if (!$this->enabled) {
            return [
                'success' => true,
                'challenge_ts' => date('Y-m-d\TH:i:s\Z'),
                'hostname' => $_SERVER['HTTP_HOST'] ?? 'unknown',
            ];
        }

        if (empty($response)) {
            return [
                'success' => false,
                'challenge_ts' => date('Y-m-d\TH:i:s\Z'),
                'hostname' => $_SERVER['HTTP_HOST'] ?? 'unknown',
                'error-codes' => ['missing-input-response']
            ];
        }

        $verifyResponse = $this->getVerificationResponse($response, $clientIp, true);

        // Store verification state
        if (isset($verifyResponse['success']) && $verifyResponse['success'] === true) {
            $this->lastScore = $verifyResponse['score'] ?? null;
            $this->verifiedResponses[] = $response;
        }

        return $verifyResponse;
    }

    /**
     * Verify the hCaptcha response.
     */
    public function verifyResponse(string $response, ?string $clientIp = null, ?bool $detailed = null)
    {
        // Use config value if $detailed is not explicitly provided
        if ($detailed === null) {
            $detailed = function_exists('config') ? config('HCaptcha.validation_return_detailed', false) : false;
        }

        if (!$this->enabled) {
            if ($detailed) {
                return [
                    'allowed' => true,
                    'action' => 'disabled',
                    'message' => 'hCaptcha is disabled',
                    'score' => null,
                    'success' => true
                ];
            }
            return true; // Always true if hCaptcha is disabled
        }

        if (empty($response)) {
            if ($detailed) {
                return [
                    'allowed' => false,
                    'action' => 'missing_response',
                    'message' => 'No hCaptcha response provided',
                    'score' => null,
                    'success' => false
                ];
            }
            return false;
        }

        // Check for existing shadow ban first
        $userId = $this->getUserIdFromIp($clientIp);
        if ($userId && $this->isUserShadowBanned($userId)) {
            $banDetails = $this->getShadowBanDetails($userId);
            if ($detailed) {
                return [
                    'allowed' => false,
                    'action' => 'shadow_ban',
                    'message' => 'Your account has been temporarily restricted due to suspicious activity.',
                    'score' => $banDetails['score'] ?? null,
                    'success' => false,
                    'ban_details' => $banDetails
                ];
            }
            return false;
        }

        // Return cached result if response already verified before.
        if (in_array($response, $this->verifiedResponses)) {
            if ($detailed) {
                return [
                    'allowed' => true,
                    'action' => 'cached',
                    'message' => 'Response already verified',
                    'score' => $this->lastScore,
                    'success' => true
                ];
            }
            return true;
        }

        $verifyResponse = $this->getVerificationResponse($response, $clientIp);
        $success = isset($verifyResponse['success']) && $verifyResponse['success'] === true;
        $score = isset($verifyResponse['score']) ? (float)$verifyResponse['score'] : null;

        $this->lastScore = $score;

        // Enhanced score-based decision making
        $result = $this->processScoreBasedDecision($success, $score, $clientIp);

        if ($result['allowed']) {
            $this->verifiedResponses[] = $response;
        }

        if ($detailed) {
            return array_merge($result, [
                'score' => $score,
                'success' => $success,
                'raw_response' => $verifyResponse
            ]);
        }

        return $result['allowed'];
    }

    /**
     * Process score-based decision according to hCaptcha recommended flow.
     *
     * Decision Matrix:
     * | Success | Score | Action | Result |
     * |---------|-------|--------|--------|
     * | true | null | Session OK | ✅ Allow |
     * | true | < 0.3 | Session OK | ✅ Allow |
     * | true | 0.3-0.7 | Trigger Re-auth | ❌ Block + Re-auth |
     * | true | ≥ 0.7 | Shadow Ban User | ❌ Block + Ban |
     * | false | null | Request New Token | ❌ Block + New Token |
     * | false | < 0.7 | Request New Token | ❌ Block + New Token |
     * | false | ≥ 0.7 | Shadow Ban User | ❌ Block + Ban |
     */
    protected function processScoreBasedDecision(bool $success, ?float $score, ?string $clientIp = null): array
    {
        $scoreThreshold = function_exists('config') ? config('HCaptcha.score_threshold', 0.7) : 0.7;
        $suspiciousThreshold = function_exists('config') ? config('HCaptcha.suspicious_score_threshold', 0.3) : 0.3;
        $userId = $this->getUserIdFromIp($clientIp);

        if ($success) {
            if ($score === null) {
                // Score missing - session OK
                return [
                    'allowed' => true,
                    'action' => 'session_ok',
                    'message' => null
                ];
            } elseif ($score >= $scoreThreshold) {
                // Score is high - shadow ban user
                $this->shadowBanUser($userId, $score);
                return [
                    'allowed' => false,
                    'action' => 'shadow_ban',
                    'message' => 'Your account has been temporarily restricted due to suspicious activity.'
                ];
            } elseif ($score >= $suspiciousThreshold) {
                // Score is suspicious - trigger re-auth
                return [
                    'allowed' => false,
                    'action' => 're_auth',
                    'message' => 'Additional verification required. Please complete the challenge again.'
                ];
            } else {
                // Score is low - session OK
                return [
                    'allowed' => true,
                    'action' => 'session_ok',
                    'message' => null
                ];
            }
        } else {
            if ($score === null || $score < $scoreThreshold) {
                // Score missing or low - request new token
                return [
                    'allowed' => false,
                    'action' => 'new_token',
                    'message' => 'Please complete the captcha challenge again.'
                ];
            } else {
                // Score is high but success is false - shadow ban user
                $this->shadowBanUser($userId, $score);
                return [
                    'allowed' => false,
                    'action' => 'shadow_ban',
                    'message' => 'Your account has been temporarily restricted due to suspicious activity.'
                ];
            }
        }
    }

    /**
     * Check if a user is shadow banned before form submission
     * This can be called before displaying forms or processing submissions
     */
    public function checkShadowBan(?string $clientIp = null, ?bool $detailed = null): bool|array
    {
        // Use config value if $detailed is not explicitly provided
        if ($detailed === null) {
            $detailed = function_exists('config') ? config('HCaptcha.validation_return_detailed', false) : false;
        }

        if (!$this->enabled) {
            return $detailed ? [
                'banned' => false,
                'action' => 'disabled',
                'message' => 'hCaptcha is disabled'
            ] : false;
        }

        $userId = $this->getUserIdFromIp($clientIp);
        if ($userId && $this->isUserShadowBanned($userId)) {
            $banDetails = $this->getShadowBanDetails($userId);
            if ($detailed) {
                return [
                    'banned' => true,
                    'action' => 'shadow_ban',
                    'message' => 'Your account has been temporarily restricted due to suspicious activity.',
                    'ban_details' => $banDetails,
                    'expires_at' => $banDetails['expires_at'] ?? null
                ];
            }
            return true;
        }

        return $detailed ? [
            'banned' => false,
            'action' => 'allowed',
            'message' => null
        ] : false;
    }

    /**
     * Get user ID from IP address (can be overridden in child classes)
     */
    protected function getUserIdFromIp(?string $clientIp = null): ?string
    {
        return $clientIp ? 'ip_' . $clientIp : null;
    }

    /**
     * Shadow ban a user due to high hCaptcha score
     */
    public function shadowBanUser(?string $userId, float $score): void
    {
        if (!$userId || (function_exists('config') && !config('HCaptcha.enable_shadow_banning', true))) {
            return;
        }

        $banKey = "hcaptcha_shadow_banned_{$userId}";
        $banDuration = function_exists('config') ? config('HCaptcha.shadow_ban_duration', 86400): 86400; // 24 hours default

        if (function_exists('cache')) {
            $now = function_exists('now') ? now() : new \DateTime();
            $bannedAt = $now instanceof \DateTime ? $now->format('c') : $now->toISOString();
            $expiresAt = function_exists('now') ? $now->addSeconds($banDuration)->toISOString() : date('c', time() + $banDuration);

            cache()->put($banKey, [
                'score' => $score,
                'banned_at' => $bannedAt,
                'expires_at' => $expiresAt
            ], $banDuration);

            // Track shadow ban keys for admin management
            $keys = cache()->get('hcaptcha_shadow_ban_keys', []);
            if (!in_array($banKey, $keys)) {
                $keys[] = $banKey;
                cache()->put('hcaptcha_shadow_ban_keys', $keys);
            }
        }

        // Log the shadow ban if detailed logging is enabled
        if (function_exists('logger') && config('HCaptcha.enable_detailed_logging', true)) {
            logger()->warning("User {$userId} shadow banned due to high hCaptcha score: {$score}", [
                'user_id' => $userId,
                'score' => $score,
                'banned_until' => now()->addSeconds($banDuration)->toISOString()
            ]);
        }
    }

    /**
     * Check if a user is shadow banned
     */
    public function isUserShadowBanned(?string $userId = null): bool
    {
        if (!$userId) {
            return false;
        }

        if (function_exists('cache')) {
            return cache()->has("hcaptcha_shadow_banned_{$userId}");
        }

        return false;
    }

    /**
     * Get shadow ban details for a user
     */
    public function getShadowBanDetails(?string $userId = null): ?array
    {
        if (!$userId) {
            return null;
        }

        if (function_exists('cache')) {
            return cache()->get("hcaptcha_shadow_banned_{$userId}");
        }

        return null;
    }

    /**
     * Remove shadow ban for a user
     */
    public function removeShadowBan(?string $userId = null): void
    {
        if (!$userId) {
            return;
        }

        if (function_exists('cache')) {
            $banKey = "hcaptcha_shadow_banned_{$userId}";
            cache()->forget($banKey);

            // Remove from keys list
            $keys = cache()->get('hcaptcha_shadow_ban_keys', []);
            $keys = array_diff($keys, [$banKey]);
            cache()->put('hcaptcha_shadow_ban_keys', $keys);
        }

        if (function_exists('logger') && config('HCaptcha.enable_detailed_logging', true)) {
            logger()->info("Shadow ban removed for user {$userId}");
        }
    }

    /**
     * Verify hCaptcha response by Symfony Request.
     */
    public function verifyRequest(Request $request): bool
    {
        return $this->verifyResponse(
            $request->get('h-captcha-response'),
            $request->getClientIp()
        );
    }

    /**
     * Send verify request.
     */
    protected function sendRequestVerify(array $query = []): array
    {
        try {
            $response = $this->http->request('POST', static::VERIFY_URL, [
                'form_params' => $query,
                'timeout' => 5.0
            ]);

            $result = json_decode($response->getBody(), true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \RuntimeException('Invalid JSON response from hCaptcha');
            }

            return $result;

        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to verify hCaptcha response');
        }
    }

    /**
     * Get the score from the last successful hCaptcha verification.
     *
     * @return float|null The score of the last verification or null if not available.
     */
    public function getScoreFromLastVerification(): ?float
    {
        return $this->lastScore;
    }

    /**
     * Render HTML captcha.
     */
    public function display($attributes = []): string
    {
        if (!$this->enabled) {
            return '';
        }

        $attributes = $this->prepareAttributes($attributes);
        return '<div' . $this->buildAttributes($attributes) . '></div>';
    }

    /**
     * @see display()
     */
    public function displayWidget($attributes = []): string
    {
        return $this->display($attributes);
    }

    /**
     * Display a Invisible hCaptcha by embedding a callback into a form submit button.
     *
     * @param string $formIdentifier the html ID of the form that should be submitted.
     * @param string $text the text inside the form button
     * @param array $attributes array of additional html elements
     *
     * @return string
     */
    public function displaySubmit(string $formIdentifier, string $text = 'submit', array $attributes = []): string
    {
        if (!$this->enabled) {
            return sprintf('<button%s><span>%s</span></button>', $this->buildAttributes($attributes), $text);
        }

        $javascript = '';
        if (!isset($attributes['data-callback'])) {
            $functionName = 'onSubmit' . str_replace(['-', '=', '\'', '"', '<', '>', '`'], '', $formIdentifier);
            $attributes['data-callback'] = $functionName;
            $javascript = sprintf(
                '<script>function %s(){document.getElementById("%s").submit();}</script>',
                $functionName,
                $formIdentifier
            );
        }

        $attributes = $this->prepareAttributes($attributes);
        $button = sprintf('<button%s><span>%s</span></button>', $this->buildAttributes($attributes), $text);

        return $button . $javascript;
    }

    /**
     * Render js source
     *
     * @param null $lang
     * @param bool $callback
     * @param string $onLoadClass
     *
     * @return string
     */
    public function renderJs($lang = null, $callback = false, $onLoadClass = 'onloadCallBack'): string
    {
        if (!$this->enabled) {
            return '';
        }

        return '<script src="' . $this->getJsLink($lang, $callback, $onLoadClass) . '" async defer></script>' . "\n";
    }

    /**
     * Get hCaptcha js link.
     *
     * @param string $lang
     * @param boolean $callback
     * @param string $onLoadClass
     *
     * @return string
     */
    public function getJsLink($lang = null, $callback = false, $onLoadClass = 'onloadCallBack'): string
    {
        if (!$this->enabled) {
            return '';
        }

        $client_api = static::CLIENT_API;
        $params = [];

        $callback ? $this->setCallBackParams($params, $onLoadClass) : false;
        $lang ? $params['hl'] = $lang : null;

        return $client_api . '?' . http_build_query($params);
    }

    /**
     * @param $params
     * @param $onLoadClass
     */
    protected function setCallBackParams(&$params, $onLoadClass): void
    {
        $params['render'] = 'explicit';
        $params['onload'] = $onLoadClass;
    }

    /**
     * Prepare HTML attributes and assure that the correct classes and attributes for captcha are inserted.
     *
     * @param array $attributes
     *
     * @return array
     */
    protected function prepareAttributes(array $attributes): array
    {
        $attributes['data-sitekey'] = $this->sitekey;
        if (!isset($attributes['class'])) {
            $attributes['class'] = '';
        }
        $attributes['class'] = trim('h-captcha ' . $attributes['class']);

        return $attributes;
    }

    /**
     * Build HTML attributes.
     *
     * @param array $attributes
     *
     * @return string
     */
    protected function buildAttributes(array $attributes): string
    {
        $html = [];

        foreach ($attributes as $key => $value) {
            $html[] = $key . '="' . $value . '"';
        }

        return count($html) ? ' ' . implode(' ', $html) : '';
    }

    /**
     * Get cached response if valid, or null if not found/expired
     */
    private function getCachedResponse(string $response): ?array
    {
        if (isset($this->responseCache[$response])) {
            $cached = $this->responseCache[$response];
            if (time() - $cached['timestamp'] < $this->cacheDuration) {
                return $cached['response'];
            }
            // Remove expired cache entry
            unset($this->responseCache[$response]);
        }
        return null;
    }

    /**
     * Cache a verification response
     */
    private function cacheResponse(string $response, array $verifyResponse): void
    {
        $this->responseCache[$response] = [
            'timestamp' => time(),
            'response' => $verifyResponse
        ];
    }

    /**
     * Get verification response, either from cache or fresh API call
     */
    private function getVerificationResponse(string $response, ?string $clientIp, bool $includeSitekey = false): array
    {
        // Try to get from cache first
        $cachedResponse = $this->getCachedResponse($response);
        if ($cachedResponse !== null) {
            return $cachedResponse;
        }

        $params = [
            'secret' => $this->secret,
            'response' => $response,
            'remoteip' => $clientIp,
        ];

        if ($includeSitekey) {
            $params['sitekey'] = $this->sitekey;
        }

        $verifyResponse = $this->sendRequestVerify($params);

        // Cache the response
        $this->cacheResponse($response, $verifyResponse);

        return $verifyResponse;
    }

}