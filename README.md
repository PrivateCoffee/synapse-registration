# Synapse Matrix Registration System

This is a user registration system for a Matrix server using Django and the Synapse Admin API. It handles user sign-ups, admin approvals, and account management.

## Features

- **User Registration Workflow**: A step-by-step registration process, including username checking, email verification, and submission of a reason for registration.
- **Admin Approval**: Registrations require admin approval before activation.
- **User Notifications**: Email notifications are sent throughout the registration process to ensure users and admins remain informed.
- **Admin Portal**: Admins can manage registrations directly from the Django admin interface, approving or denying requests.

## Installation

1. **Clone the Repository**:

```bash
git clone https://git.private.coffee/PrivateCoffee/synapse-registration.git
cd synapse-registration
python3 -m venv venv
source venv/bin/activate
pip install .
```

2. **Create configuration file**:

```bash
cp config.dist.yaml config.yaml
```

3. **Edit configuration file**:

Edit the `config.yaml` file to match your Matrix server and email settings.

The following settings are available:

- `debug`: Set to `true` to enable Django debug mode. Do not enable in production.
- `secret_key`: Django secret key. If not set, a random key will be generated on startup.
- `synapse`: Synapse server settings.
  - `admin_token`: Access token of an admin user.
  - `server`: Synapse server URL (e.g. `https://matrix.example.com`).
  - `domain`: Matrix server domain (e.g. `example.com`).
  - `verify_cert`: If your Synapse server uses a self-signed certificate, set this to `false`, or provide the path to your CA bundle.
- `hosts`: List of domains that the registration system will be accessible at. At least one domain is required.
- `email`: Email server settings.
  - `host`: SMTP server hostname. Required.
  - `port`: SMTP server port. Required.
  - `username`: SMTP username. Required.
  - `password`: SMTP password. Required.
  - `tls`: Set to `true` to enable STARTTLS.
  - `ssl`: Set to `true` to enable SSL.
  - `from`: Email address to send notifications from. Defaults to the `username` setting.
- `admin`: Admin user settings.
  - `email`: Email address to send admin notifications to. Required.
- `trust_proxy`: Set to `true` if the registration system is behind a reverse proxy. This ensures the correct IP address is logged.
- `auto_join`: Optional list of rooms to automatically join users to after registration. The admin user must be in these rooms and have invite permissions.
- `legal`: Optional list of legal documents to link to in the registration form. Each item must have a `title` and `url`.
- `retention`: Optional retention periods for registrations.
  - `started`: Days to keep unverified registrations. Default is 2 days.
  - `completed`: Days to keep completed/denied registrations. Default is 30 days.
- `database`: Optional database settings.
  - `path`: Path to the SQLite database file. Defaults to `db.sqlite3` in the current directory.

4. **Run migrations**:

```bash
synapse_registration migrate
```

5. **Create superuser**:

```bash
synapse_registration createsuperuser
```

6. **Run the server**:

For development:

```bash
synapse_registration runserver
```

For production, use a WSGI server such as uWSGI, behind a reverse proxy such as Caddy.

## Usage

1. **Access the registration system**:

Navigate to the domain you set in the `config.yaml` file. You should see the registration form.

2. **Register a new user**:

The registration process is as follows:

- **Step 1**: Enter a username. The system will check if the username is available.
- **Step 2**: Enter an email address. A verification email will be sent.
- **Step 3**: Enter a password and reason for registration. The password will be stored in Synapse, the reason will be stored in the admin interface.
- **Step 4**: Wait for an admin to approve the registration. You will receive an email when this happens.

3. **Approve a registration**:

- **Step 1**: Log in to the Django admin interface.
- **Step 2**: Navigate to the `User registrations` section.
- **Step 3**: Review the registration request and set the status to `Approved` or `Denied`. This will enable the Matrix account and send an email to the user.

4. **Clean up registrations**:

**Note**: This is no longer necessary. Old registrations are automatically cleaned up.

You can use the `synapse_registration cleanup` command to remove old registration requests.

- Unverified registrations are removed after 48 hours.
- Denied and approved registrations are removed after 30 days.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
