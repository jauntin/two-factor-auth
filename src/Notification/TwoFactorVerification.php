<?php

namespace Jauntin\TwoFactorAuth\Notification;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Address;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Jauntin\TwoFactorAuth\Contracts\TwoFactorMailable;

class TwoFactorVerification extends Mailable implements TwoFactorMailable
{
    use Queueable;

    private string $verificationCode;

    public function envelope(): Envelope
    {
        return new Envelope(
            from: new Address('no-reply@jauntin.com', 'Jauntin'),
            subject: 'Verification code',
        );
    }

    public function content(): Content
    {
        return new Content(
            text: 'Your verification code: '.$this->verificationCode,
        );
    }

    public function setVerificationCode(string $verificationCode): self
    {
        $this->verificationCode = $verificationCode;

        return $this;
    }
}
