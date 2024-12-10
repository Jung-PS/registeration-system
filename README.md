# Registration System - Jung-PS

## Description

This is a user management and registration system built with Flask. It includes features for user authentication, registration, and role-based access control. The system also incorporates QR code validation, profile management, and admin capabilities to manage users and news updates. It leverages bcrypt for password hashing and Cloudflare Turnstile for CAPTCHA verification.

---

## Features

1. **User Authentication**:
   - Login/logout functionality.
   - Session management for authenticated users.

2. **User Roles**:
   - **Admin**: Manage users, update news, and site settings.
   - **Checker**: Approve or reject user accounts.
   - **Viewer**: Access to view-specific data.
   - **User**: Standard user functionalities.

3. **Registration**:
   - CAPTCHA verification using Cloudflare Turnstile.
   - QR code scanning for profile validation.
   - Profile picture upload with size and format restrictions.

4. **Admin Functions**:
   - Add, edit, and delete users.
   - Update news and site content.
   - Toggle registration availability.

5. **Dynamic Web Content**:
   - News updates displayed on the homepage.
   - Embed page for additional content.

6. **QR Code Validation**:
   - Users are validated through a QR code scan during registration.

---

## Installation

### Prerequisites
- Python 3.8 or higher.
- Pip for Python package management.
- A virtual environment is recommended for dependency management.

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repository/jung-ps-registration.git
   cd jung-ps-registration
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create necessary directories and files:
   ```bash
   mkdir static/uploads
   touch users.json news.json
   ```

4. Add default content to `users.json` and `news.json`:
   - `users.json`:
     ```json
     {}
     ```
   - `news.json`:
     ```json
     {
       "news": {
         "title": "",
         "content": ""
       },
       "register": {
         "status": "open",
         "content": ""
       },
       "web": {
         "content": ""
       }
     }
     ```

5. Update secret keys in the code:
   - Replace `SECRET` with your custom secret keys for Flask and Turnstile.

---

## Usage

1. **Start the Server**:
   Run the Flask application:
   ```bash
   python app.py
   ```
   The server will be available at `http://127.0.0.1:5000`.

2. **Access the Web Interface**:
   - Visit the home page: `http://127.0.0.1:5000/`.
   - Admin users can access the admin dashboard after logging in.

3. **Register Users**:
   - Ensure registration is open via admin settings.
   - New users can register through the registration form.

---

## Routes

| Route                     | Method | Description                                |
|---------------------------|--------|--------------------------------------------|
| `/`                       | GET    | Homepage for logged-in users.              |
| `/login`                  | GET/POST | User login.                               |
| `/logout`                 | GET    | Logs out the current user.                 |
| `/register`               | GET/POST | User registration.                        |
| `/check/<username>`       | POST   | Toggles user approval (admin/checker).     |
| `/reject/<username>`      | POST   | Rejects a user account (admin/checker).    |
| `/edit_user/<username>`   | POST   | Edits a user's details (admin only).       |
| `/delete_user/<username>` | POST   | Deletes a user (admin only).               |
| `/update_news`            | POST   | Updates news content (admin only).         |
| `/update_web`             | POST   | Updates web content (admin only).          |
| `/update_register`        | POST   | Toggles registration availability (admin). |
| `/embed`                  | GET    | Displays additional content.               |

---

## Dependencies

- **Flask**: Web framework.
- **bcrypt**: Secure password hashing.
- **pytz**: Timezone management.
- **requests**: HTTP requests for Turnstile verification.
- **OpenCV (cv2)**: QR code detection.
- **Werkzeug**: Secure filename handling.

---

## Security Considerations

- Ensure secret keys (`app.secret_key` and `TURNSTILE_SECRET_KEY`) are kept secure.
- Use HTTPS in production for secure data transmission.
- Validate uploaded files rigorously to prevent malicious file uploads.

---

## Contribution

Feel free to fork the repository and submit pull requests for new features or bug fixes. For major changes, please open an issue first to discuss what you would like to change.

---
