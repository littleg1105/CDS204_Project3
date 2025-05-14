# Admin OTP Setup Instructions

## Overview
The admin interface is now protected by Two-Factor Authentication (2FA) using Time-based One-Time Passwords (TOTP).
This provides an extra layer of security for the admin interface.

## Setup Steps

1. **Admin Account**
   - Username: `XXXXX`
   - Password: `XXXXXXXXX`

2. **OTP Authentication**
   - OTP has been set up for the admin user
   - A QR code has been generated and saved as `admin_qrcode.png` in the project root
   - Scan this QR code with an authenticator app like Google Authenticator, Microsoft Authenticator, or Authy

3. **Backup Codes**
   The following backup codes have been generated and can be used if you lose access to your authenticator app:
   - bi3b3vsj
   - 5kovvnfg
   - setgr22o
   - nippcs7o
   - yjoxjqwt

## How to Login

1. Navigate to the admin interface at `https://localhost:8000/admin/`
2. Enter your username and password
3. You will be redirected to a second page asking for your OTP code
4. Open your authenticator app and enter the code shown there
5. If you don't have access to your authenticator app, you can use one of the backup codes

## Running the Server

```bash
python manage.py runserver_plus --cert-file=certificates/cert.pem --key-file=certificates/key.pem
```

## Resetting the OTP Setup

If you need to reset the OTP setup, run the following command:

```bash
python manage.py add_otp_device admin
```

This will generate a new QR code and backup codes.

## Generating OTP for Other Users

To set up OTP for other users, run:

```bash
python manage.py add_otp_device <username>
```

This will create an OTP device for the specified user and generate a QR code and backup codes.