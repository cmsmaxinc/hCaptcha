<?php

namespace Scyllaly\HCaptcha\Tests;

use PHPUnit\Framework\TestCase;
use Scyllaly\HCaptcha\HCaptcha;

class BasicHCaptchaTest extends TestCase
{
    /**
     * @var HCaptcha
     */
    private $captcha;

    public function setUp(): void
    {
        parent::setUp();
        $this->captcha = new HCaptcha('test-secret', 'test-sitekey');
    }

    public function testEnhancedMethodsExist()
    {
        $this->assertTrue(method_exists($this->captcha, 'verifyResponse'));
        $this->assertTrue(method_exists($this->captcha, 'shadowBanUser'));
        $this->assertTrue(method_exists($this->captcha, 'isUserShadowBanned'));
        $this->assertTrue(method_exists($this->captcha, 'getShadowBanDetails'));
        $this->assertTrue(method_exists($this->captcha, 'removeShadowBan'));
        $this->assertTrue(method_exists($this->captcha, 'getResponseDetails'));
        $this->assertTrue(method_exists($this->captcha, 'getScoreFromLastVerification'));
    }

    public function testProtectedMethodsExist()
    {
        $reflection = new \ReflectionClass($this->captcha);
        
        $this->assertTrue($reflection->hasMethod('processScoreBasedDecision'));
        $this->assertTrue($reflection->hasMethod('getUserIdFromIp'));
    }

    public function testBasicDisplayMethods()
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

    public function testConstructor()
    {
        $this->assertInstanceOf(HCaptcha::class, $this->captcha);
    }

    public function testDisabledCaptcha()
    {
        $disabledCaptcha = new HCaptcha('test-secret', 'test-sitekey', [], false);
        $this->assertInstanceOf(HCaptcha::class, $disabledCaptcha);
    }
} 