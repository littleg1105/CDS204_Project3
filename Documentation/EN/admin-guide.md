# Admin Guide

This guide provides detailed instructions for administrators of the Secure E-Shop application, including how to set up and manage the admin interface with Two-Factor Authentication.

## Admin Interface Overview

The Django admin interface for Secure E-Shop provides access to:

- **Products**: Add, edit, and remove products from the catalog
- **Users**: Manage user accounts
- **Orders**: View and manage customer orders
- **Shopping Carts**: View current user shopping carts

The admin interface is protected by:
1. Username/password authentication
2. Two-Factor Authentication (2FA) using Time-based One-Time Passwords (TOTP)

## Accessing the Admin Interface

The admin interface is available at:
- Local development: https://localhost:8000/admin/
- Production: https://yourdomain.com/admin/

## Two-Factor Authentication Setup

### Initial OTP Setup

As of May 14, 2025, the admin interface requires Two-Factor Authentication. To set up OTP for the admin user:

1. Run the following command:
   ```bash
   python manage.py add_otp_device admin
   ```

2. This will generate a QR code saved as `admin_qrcode.png` in the project root directory.

3. Scan this QR code with an authenticator app like:
   - Google Authenticator
   - Microsoft Authenticator
   - Authy

### Backup Codes

The setup process also generates backup codes that can be used if you lose access to your authenticator app. These are displayed in the terminal when you run the command and should be stored securely.

Example backup codes:
```
bi3b3vsj
5kovvnfg
setgr22o
nippcs7o
yjoxjqwt
```

## Login Process with 2FA

1. Navigate to the admin interface at `https://localhost:8000/admin/` (or your production URL)
2. Enter your username and password
3. You will be redirected to a second page asking for your OTP code
4. Open your authenticator app and enter the 6-digit code shown there
5. If you don't have access to your authenticator app, you can use one of the backup codes

## Resetting OTP Setup

If you need to reset the OTP setup (e.g., lost phone with authenticator app, used all backup codes), run:

```bash
python manage.py add_otp_device admin
```

This will generate a new QR code and backup codes, invalidating the previous setup.

## Setting Up OTP for Other Admin Users

To set up OTP for other admin users:

```bash
python manage.py add_otp_device <username>
```

This will create an OTP device for the specified user and generate a QR code and backup codes.

## Managing Products

### Adding a New Product

1. Navigate to **Products** in the admin panel
2. Click **Add Product**
3. Fill in the product details:
   - Name
   - Description
   - Price
   - Image (optional)
4. Click **Save**

### Editing Products

1. Navigate to **Products** in the admin panel
2. Click on the product you want to edit
3. Update the details
4. Click **Save**

### Bulk Actions

You can perform bulk actions on products:
1. Select multiple products using the checkboxes
2. Choose an action from the dropdown (e.g., Delete selected products)
3. Click **Go**

## Managing Orders

### Viewing Orders

1. Navigate to **Orders** in the admin panel
2. Click on an order to view details

### Updating Order Status

1. Open the order
2. Change the status field (e.g., from "Processing" to "Shipped")
3. Click **Save**

## User Management

### Creating Admin Users

To create another admin user:

1. Navigate to **Users** in the admin panel
2. Click **Add User**
3. Fill in the username and password
4. Click **Save**
5. On the next screen, check "Staff status" and "Superuser status"
6. Click **Save**
7. Set up OTP for the new admin user using the command mentioned earlier

### Modifying User Permissions

1. Navigate to **Users** in the admin panel
2. Click on the user
3. Update the permissions as needed
4. Click **Save**

## System Monitoring

### Checking Login Attempts

To monitor failed login attempts (possible security breaches):

1. Navigate to **Access attempts** in the admin panel
2. Review the list of failed attempts, which includes:
   - Username
   - IP address
   - User agent
   - Time of attempt

### Reviewing Logs

For more detailed monitoring, check the application logs:

```bash
# View the last 100 lines of the application log
tail -n 100 logs/app.log

# Monitor the log in real-time
tail -f logs/app.log
```

In production, logs might be in a different location depending on your configuration.

## Backup and Restore

### Database Backup

To create a backup of the database:

```bash
# SQLite (Development)
cp db.sqlite3 db.sqlite3.backup

# MySQL (Production)
mysqldump -u username -p database_name > backup.sql
```

### Restoring from Backup

```bash
# SQLite (Development)
cp db.sqlite3.backup db.sqlite3

# MySQL (Production)
mysql -u username -p database_name < backup.sql
```

## Email Configuration

The system sends order confirmation emails. To configure email settings:

1. Update the `.env` file with your email credentials:
   ```
   EMAIL_HOST_USER=your-email@example.com
   EMAIL_HOST_PASSWORD=your-app-password
   ```

2. For Gmail, you'll need to generate an "App Password" in your Google Account security settings.

## Troubleshooting

### OTP Issues

If administrators are having trouble with OTP:

1. Verify the time on their authenticator app device is correct
2. Consider resetting their OTP device with `python manage.py add_otp_device username`
3. Use backup codes if available

### Login Lockouts

If an administrator is locked out due to too many failed attempts:

1. Check the Access Attempts in the admin panel
2. Reset the lockout using Django shell:
   ```bash
   python manage.py shell
   
   # In the shell
   from axes.utils import reset
   reset()  # Reset all lockouts
   
   # Or reset for a specific username
   reset(username='admin')
   ```

### Error Logs

Always check application logs for detailed error information:
```bash
tail -n 100 logs/app.log
```

## Security Best Practices

1. **Change Default Credentials**: Always change default admin credentials
2. **Regular Backups**: Perform regular database backups
3. **Monitor Login Attempts**: Regularly check for suspicious login attempts
4. **Update Regularly**: Keep Django and all dependencies updated
5. **Use Strong Passwords**: Enforce strong password policy for all admin users
6. **Limit Admin Access**: Restrict admin access to necessary personnel only
7. **Two-Factor Authentication**: Ensure all admin users have 2FA enabled
