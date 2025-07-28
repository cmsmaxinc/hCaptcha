<?php

namespace Scyllaly\HCaptcha\Tests;

use PHPUnit\Framework\TestCase;
use Scyllaly\HCaptcha\HCaptcha;

/**
 * @group laravel
 */
class EnhancedHCaptchaTest extends TestCase
{
    private HCaptcha $captcha;

    public function setUp(): void
    {
        parent::setUp();
        $this->captcha = new HCaptcha('test-secret', 'test-sitekey');
        
    }

    public function testBasicVerification()
    {
        $this->assertInstanceOf(HCaptcha::class, $this->captcha);
    }

    public function testGetDetailedVerificationResultWithDisabledCaptcha()
    {
        $disabledCaptcha = new HCaptcha('test-secret', 'test-sitekey', [], false);
        
        $result = $disabledCaptcha->verifyResponse('test-response', null, true);
        
        $this->assertTrue($result['allowed']);
        $this->assertEquals('disabled', $result['action']);
        $this->assertEquals('hCaptcha is disabled', $result['message']);
        $this->assertTrue($result['success']);
        $this->assertNull($result['score']);
    }

    public function testGetDetailedVerificationResultWithEmptyResponse()
    {
        $result = $this->captcha->verifyResponse('', null, true);
        
        $this->assertFalse($result['allowed']);
        $this->assertEquals('missing_response', $result['action']);
        $this->assertEquals('No hCaptcha response provided', $result['message']);
        $this->assertFalse($result['success']);
        $this->assertNull($result['score']);
    }

    public function testShadowBanUser()
    {
        $userId = 'test_user_123';
        $score = 0.8;
        
        $this->captcha->shadowBanUser($userId, $score);
        
        $this->assertTrue(method_exists($this->captcha, 'isUserShadowBanned'));
        $this->assertTrue(method_exists($this->captcha, 'getShadowBanDetails'));
    }

    public function testRemoveShadowBan()
    {
        $userId = 'test_user_456';
        $score = 0.9;
        
        // Test that the methods exist and don't throw errors
        $this->captcha->shadowBanUser($userId, $score);
        $this->captcha->removeShadowBan($userId);
        
        $this->assertTrue(method_exists($this->captcha, 'removeShadowBan'));
    }

    public function testShadowBanWithNullUserId()
    {
        // Test that the method exists and doesn't throw errors with null userId
        $this->captcha->shadowBanUser(null, 0.8);
        $this->assertTrue(method_exists($this->captcha, 'isUserShadowBanned'));
    }

    public function testGetUserIdFromIp()
    {
        $reflection = new \ReflectionClass($this->captcha);
        $method = $reflection->getMethod('getUserIdFromIp');
        $method->setAccessible(true);
        
        $userId = $method->invoke($this->captcha, '192.168.1.1');
        $this->assertEquals('ip_192.168.1.1', $userId);
        
        $userId = $method->invoke($this->captcha, null);
        $this->assertNull($userId);
    }

    public function testProcessScoreBasedDecision()
    {
        $reflection = new \ReflectionClass($this->captcha);
        $method = $reflection->getMethod('processScoreBasedDecision');
        $method->setAccessible(true);
        
        // Test success with null score (session OK)
        $result = $method->invoke($this->captcha, true, null, '192.168.1.1');
        $this->assertTrue($result['allowed']);
        $this->assertEquals('session_ok', $result['action']);
        $this->assertNull($result['message']);
        
        // Test success with low score (session OK) - below 0.3 threshold
        $result = $method->invoke($this->captcha, true, 0.2, '192.168.1.1');
        $this->assertTrue($result['allowed']);
        $this->assertEquals('session_ok', $result['action']);
        $this->assertNull($result['message']);
        
        // Test success with suspicious score (re-auth) - between 0.3 and 0.7
        $result = $method->invoke($this->captcha, true, 0.5, '192.168.1.1');
        $this->assertFalse($result['allowed']);
        $this->assertEquals('re_auth', $result['action']);
        $this->assertStringContainsString('Additional verification required', $result['message']);
        
        // Test success with high score (shadow ban) - above 0.7
        $result = $method->invoke($this->captcha, true, 0.8, '192.168.1.1');
        $this->assertFalse($result['allowed']);
        $this->assertEquals('shadow_ban', $result['action']);
        $this->assertStringContainsString('temporarily restricted', $result['message']);
        
        // Test failure with low score (new token) - below 0.7
        $result = $method->invoke($this->captcha, false, 0.2, '192.168.1.1');
        $this->assertFalse($result['allowed']);
        $this->assertEquals('new_token', $result['action']);
        $this->assertStringContainsString('complete the captcha challenge', $result['message']);
        
        // Test failure with high score (shadow ban) - above 0.7
        $result = $method->invoke($this->captcha, false, 0.8, '192.168.1.1');
        $this->assertFalse($result['allowed']);
        $this->assertEquals('shadow_ban', $result['action']);
        $this->assertStringContainsString('temporarily restricted', $result['message']);
    }

    public function testGetResponseDetailsWithDisabledCaptcha()
    {
        $disabledCaptcha = new HCaptcha('test-secret', 'test-sitekey', [], false);
        
        $result = $disabledCaptcha->getResponseDetails('test-response');
        
        $this->assertTrue($result['success']);
        $this->assertArrayHasKey('challenge_ts', $result);
        $this->assertArrayHasKey('hostname', $result);
    }

    public function testGetResponseDetailsWithEmptyResponse()
    {
        $result = $this->captcha->getResponseDetails('');
        
        $this->assertFalse($result['success']);
        $this->assertArrayHasKey('error-codes', $result);
        $this->assertContains('missing-input-response', $result['error-codes']);
    }

    public function testGetScoreFromLastVerification()
    {
        // Initially should be null
        $this->assertNull($this->captcha->getScoreFromLastVerification());
        
        // After verification, should return the score
        $reflection = new \ReflectionClass($this->captcha);
        $property = $reflection->getProperty('lastScore');
        $property->setAccessible(true);
        $property->setValue($this->captcha, 0.75);
        
        $this->assertEquals(0.75, $this->captcha->getScoreFromLastVerification());
    }

    public function testVerifyRequest()
    {
        $this->assertTrue(method_exists($this->captcha, 'verifyRequest'));
    }

    public function testDisplayMethods()
    {
        $this->assertIsString($this->captcha->display());
        $this->assertIsString($this->captcha->displayWidget());
        $this->assertIsString($this->captcha->renderJs());
        $this->assertIsString($this->captcha->getJsLink());
    }

    public function testDisplaySubmit()
    {
        $result = $this->captcha->displaySubmit('test-form', 'Submit');
        $this->assertIsString($result);
        $this->assertStringContainsString('test-form', $result);
        $this->assertStringContainsString('Submit', $result);
    }
} 