# hCaptcha
The package is one of the recommended package on [the official developer guide of HCaptcha](https://github.com/hCaptcha/hcaptcha-integrations-list#laravel).

- Purchase a [VPS](https://bwh88.net/aff.php?aff=20075) for developing and deploying applications.

## Installation

```
composer require scyllaly/hcaptcha
```

## Laravel 5 and above

### Setup

In `app/config/app.php` add the following :

1- The ServiceProvider to the providers array :

```php
Scyllaly\HCaptcha\HCaptchaServiceProvider::class,
```

2- The class alias to the aliases array :

```php
'HCaptcha' => Scyllaly\HCaptcha\Facades\HCaptcha::class,
```

3- Publish the config file

```ssh
php artisan vendor:publish --provider="Scyllaly\HCaptcha\HCaptchaServiceProvider"
```

### Configuration

Add `HCAPTCHA_SECRET` and `HCAPTCHA_SITEKEY` in **.env** file :

```
HCAPTCHA_SECRET=secret-key
HCAPTCHA_SITEKEY=site-key
```

(You can obtain them from [here](https://docs.hcaptcha.com/api#getapikey))

### Usage

#### Init js source

With default options :

```php
 {!! HCaptcha::renderJs() !!}
```

With [language support](https://docs.hcaptcha.com/configuration) or [onloadCallback](https://docs.hcaptcha.com/configuration) option :

```php
 {!! HCaptcha::renderJs('fr', true, 'hcaptchaCallback') !!}
```

#### Display hCAPTCHA

Default widget :

```php
{!! HCaptcha::display() !!}
```

With [custom attributes](https://docs.hcaptcha.com/configuration#themes) (theme, size, callback ...) :

```php
{!! HCaptcha::display(['data-theme' => 'dark']) !!}
```

Invisible hCAPTCHA using a [submit button](https://docs.hcaptcha.com/configuration#themes):

```php
{!! HCaptcha::displaySubmit('my-form-id', 'submit now!', ['data-theme' => 'dark']) !!}
```
Notice that the id of the form is required in this method to let the autogenerated 
callback submit the form on a successful captcha verification.

#### Validation

Add `'h-captcha-response' => 'required|HCaptcha'` to rules array :

```php
$validate = Validator::make(Input::all(), [
	'h-captcha-response' => 'required|HCaptcha'
]);

```

##### Custom Validation Message

Add the following values to the `custom` array in the `validation` language file :

```php
'custom' => [
    'h-captcha-response' => [
        'required' => 'Please verify that you are not a robot.',
        'h_captcha' => 'Captcha error! try again later or contact site admin.',
    ],
],
```

Then check for captcha errors in the `Form` :

```php
@if ($errors->has('h-captcha-response'))
    <span class="help-block">
        <strong>{{ $errors->first('h-captcha-response') }}</strong>
    </span>
@endif
```

### Testing

When using the [Laravel Testing functionality](http://laravel.com/docs/5.5/testing), you will need to mock out the response for the captcha form element.

So for any form tests involving the captcha, you can do this by mocking the facade behavior:

```php
// prevent validation error on captcha
HCaptcha::shouldReceive('verifyResponse')
    ->once()
    ->andReturn(true);

// provide hidden input for your 'required' validation
HCaptcha::shouldReceive('display')
    ->zeroOrMoreTimes()
    ->andReturn('<input type="hidden" name="h-captcha-response" value="1" />');
```

You can then test the remainder of your form as normal.

When using HTTP tests you can add the `h-captcha-response` to the request body for the 'required' validation:

```php
// prevent validation error on captcha
HCaptcha::shouldReceive('verifyResponse')
    ->once()
    ->andReturn(true);

// POST request, with request body including `h-captcha-response`
$response = $this->json('POST', '/register', [
    'h-captcha-response' => '1',
    'name' => 'John',
    'email' => 'john@example.com',
    'password' => '123456',
    'password_confirmation' => '123456',
]);
```

## Without Laravel

Checkout example below:

```php
<?php

require_once "vendor/autoload.php";

$secret  = 'CAPTCHA-SECRET';
$sitekey = 'CAPTCHA-SITEKEY';
$captcha = new \Scyllaly\HCaptcha\HCaptcha($secret, $sitekey);

if (! empty($_POST)) {
    var_dump($captcha->verifyResponse($_POST['h-captcha-response']));
    exit();
}

?>

<form action="?" method="POST">
    <?php echo $captcha->display(); ?>
    <button type="submit">Submit</button>
</form>

<?php echo $captcha->renderJs(); ?>
```
