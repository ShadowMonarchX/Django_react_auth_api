---

```markdown
# 🔐 Django + React Authentication API

A full-stack authentication system built using Django (REST Framework) on the backend and React on the frontend. It uses **JWT tokens** for secure authentication, supports user registration, login, logout, and protected routes.

## 🧰 Tech Stack

### Backend (Django REST)
- Django
- Django REST Framework
- djangorestframework-simplejwt
- CORS Headers

### Frontend (React)
- React
- Axios
- React Router DOM

---

## 🗂️ Project Structure

```

Django\_react\_auth\_api/
├── backend/
│   ├── backend/              # Django project settings
│   ├── api/                  # Main app with views, urls, models
│   ├── manage.py
│   └── requirements.txt
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/       # Login, Register, Dashboard
│   │   ├── App.js
│   │   └── index.js
│   ├── package.json
└── README.md

````

---

## ⚙️ Backend Setup (Django)

1. **Create & activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
````

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run migrations**

   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

4. **Start Django server**

   ```bash
   python manage.py runserver
   ```

5. **API Endpoints**

   ```
   POST   /api/register/     -> Register user
   POST   /api/token/        -> Get access & refresh token
   POST   /api/token/refresh/-> Refresh access token
   GET    /api/user/         -> Get user info (requires auth)
   ```

---

## ⚛️ Frontend Setup (React)

1. **Navigate to frontend folder**

   ```bash
   cd frontend
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Start React dev server**

   ```bash
   npm start
   ```

4. React app runs on: `http://localhost:3000`
   Django backend runs on: `http://localhost:8000`

---

## 🔐 Authentication Flow (JWT)

* User registers → gets stored in Django DB.
* User logs in → gets **JWT access** & **refresh token**.
* Tokens are stored in **localStorage** (or memory).
* Protected routes check access token.
* If token is expired → use refresh token to get new one.

---

## 🌐 CORS Setup (Backend)

In `settings.py`:

```python
INSTALLED_APPS = [
    ...
    'corsheaders',
    ...
]

MIDDLEWARE = [
    ...
    'corsheaders.middleware.CorsMiddleware',
    ...
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
]
```

---

## 🧪 Testing

You can test APIs using:

* Postman
* Curl
* React frontend forms

---

## ✅ Features

* ✅ User registration & login
* ✅ JWT-based authentication
* ✅ Token refresh
* ✅ Protected user routes
* ✅ React frontend with route protection
* ✅ CORS configured for dev

---

## 🚀 Future Improvements

* Password reset via email
* Admin dashboard
* Role-based access (user/admin)
* Docker support
* CI/CD Pipeline

---

## 🤝 Contributing

1. Fork the repository
2. Create a new branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m "Added feature"`
4. Push to the branch: `git push origin feature-name`
5. Open a Pull Request

---

## 📄 License

MIT License. See `LICENSE` for details.

---

## 📬 Contact

Made with ❤️ by \Jenish Shekhada
GitHub: [https://github.com/ShadowMonarchX](https://github.com/ShadowMonarchX)

```

---

Would you like me to also generate the full **`requirements.txt`**, `views.py`, `serializers.py`, or React components (`Login.js`, `Register.js`, etc.) to go with this README?
```
