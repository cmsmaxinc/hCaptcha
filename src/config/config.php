<?php

return [
    'secret'            => env('HCAPTCHA_SECRET'),
    'sitekey'           => env('HCAPTCHA_SITEKEY'),
    'enabled'           => env('HCAPTCHA_ENABLED', true), //Enable or disable hCaptcha for development environments
    'server-get-config' => false,
    'options'           => [
        'timeout' => 30,
    ],
    'score_verification_enabled' => false, // Enterprise feature to enable score-based verification
    'score_threshold' => 0.7, // Any requests above this score will be considered as spam
    'suspicious_score_threshold' => 0.3, // Score threshold for triggering re-authentication
    'shadow_ban_duration' => 86400, // Shadow ban duration in seconds (24 hours)
    'enable_shadow_banning' => true, // Enable shadow banning feature
    'enable_detailed_logging' => true, // Enable detailed logging for shadow bans
    'validation_return_detailed' => false, // Whether validation rules return detailed results by default
];
