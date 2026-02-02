# RENT HUB - E-commerce Renting Platform

A full-stack web application that enables users to rent out items like electronics, vehicles, books, and more, promoting sustainability through item sharing and reducing waste.

## 🚀 Features

### User Features
- **Secure Authentication**: User registration and login with JWT tokens
- **Two-Factor Authentication (2FA)**: Enhanced security with TOTP-based 2FA
- **Profile Management**: Update personal information, view login history
- **Product Listings**: Browse approved rental items with filtering and search
- **Shopping Cart**: Add items to cart with quantity and duration management
- **Wishlist**: Save favorite items for later
- **Reviews & Ratings**: Rate and review rented items
- **Real-time Chat**: Communicate with product owners
- **Order History**: Track rental history and ratings

### Admin Features
- **Dashboard**: Comprehensive admin panel for platform management
- **User Management**: View and manage all registered users
- **Product Approval**: Approve or reject product listings with reasons
- **Chat Management**: Monitor and send admin messages
- **System Health**: Database connection monitoring

### Security Features
- Rate limiting to prevent abuse
- Strong password policies
- Account lockout after failed login attempts
- IP-based security tracking
- Secure file uploads with validation

## 🛠 Tech Stack

### Backend
- **Flask**: Python web framework
- **MongoDB**: NoSQL database for data storage
- **JWT (JSON Web Tokens)**: Secure authentication
- **Werkzeug**: Password hashing and security utilities
- **Flask-CORS**: Cross-origin resource sharing
- **Flask-Limiter**: API rate limiting
- **PyOTP**: Two-factor authentication
- **QRCode**: QR code generation for 2FA setup

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Responsive styling
- **JavaScript (ES6+)**: Interactive functionality
- **Responsive Design**: Mobile-friendly interface

### Development Tools
- **Python-dotenv**: Environment variable management
- **Requests**: HTTP client for external APIs
- **Logging**: Comprehensive application logging

## 📋 Prerequisites

- Python 3.8 or higher
- MongoDB 4.0 or higher
- pip (Python package installer)

## 🔧 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/renthub.git
   cd renthub
   ```

2. **Create virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up MongoDB**
   - Install MongoDB locally or use MongoDB Atlas
   - Create a database named 'renthub'

5. **Configure environment variables**
   Create a `.env` file in the root directory:
   ```env
   SECRET_KEY=your-secret-key-here
   MONGO_URI=mongodb://localhost:27017/renthub
   ADMIN_EMAIL=admin@renthub.com
   ADMIN_PASSWORD=admin123
   ```

6. **Run the application**
   ```bash
   python backend/app.py
   ```

7. **Access the application**
   - Frontend: http://localhost:5000
   - API endpoints: http://localhost:5000/api/

## 📖 Usage

### For Users
1. **Register**: Create a new account with email and password
2. **Login**: Access your account (admin login: admin@renthub.com / admin123)
3. **Browse Products**: View approved listings with filters
4. **Create Listings**: Add your items for rent with images and certificates
5. **Manage Cart**: Add items, specify rental duration
6. **Communicate**: Chat with owners about rentals

### For Admins
1. **Login as Admin**: Use admin credentials
2. **Approve Listings**: Review and approve/reject product submissions
3. **Manage Users**: View user details and activity
4. **Monitor Chats**: Oversee user communications

## 🗂 Project Structure

```
RENTHUB001/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── utils/
│   │   └── security.py        # Security utilities
│   └── uploads/               # File uploads directory
│       ├── images/            # Product images
│       └── certs/             # Product certificates
├── frontend/
│   ├── index.html             # Homepage
│   ├── auth.html              # Authentication page
│   ├── products.html          # Product listings
│   ├── product.html           # Individual product page
│   ├── cart.html              # Shopping cart
│   ├── admin.html             # Admin dashboard
│   ├── profile.html           # User profile
│   ├── style.css              # Main stylesheet
│   └── script.js              # Main JavaScript file
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```

## 🔌 API Endpoints

### Authentication
- `POST /api/signup` - User registration
- `POST /api/login` - User login
- `POST /api/admin/login` - Admin login

### User Management
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update profile
- `POST /api/change-password` - Change password
- `POST /api/setup-2fa` - Setup 2FA
- `POST /api/verify-2fa-setup` - Verify 2FA setup
- `POST /api/toggle-2fa` - Enable/disable 2FA
- `GET /api/login-history` - Get login history
- `POST /api/deactivate-account` - Deactivate account

### Products
- `GET /api/products` - Get product listings
- `GET /api/products/:id` - Get single product
- `POST /api/products` - Create product listing
- `GET /api/categories/counts` - Get category counts

### Admin
- `GET /api/admin/products` - Get all products (admin)
- `POST /api/admin/products/:id/approve` - Approve product
- `POST /api/admin/products/:id/reject` - Reject product
- `GET /api/admin/users` - Get all users
- `GET /api/admin/chat/messages` - Get all chat messages
- `POST /api/admin/chat/send` - Send admin message

### Cart & Wishlist
- `GET /api/cart` - Get user cart
- `POST /api/cart/add` - Add to cart
- `POST /api/cart/remove` - Remove from cart
- `POST /api/cart/update` - Update cart item
- `POST /api/cart/clear` - Clear cart
- `GET /api/wishlist` - Get wishlist
- `POST /api/wishlist/add` - Add to wishlist
- `POST /api/wishlist/remove` - Remove from wishlist

### Reviews & Chat
- `POST /api/reviews` - Submit review
- `GET /api/reviews/:product_id` - Get product reviews
- `GET /api/reviews/user` - Get user reviews
- `PUT /api/reviews/:id` - Update review
- `DELETE /api/reviews/:id` - Delete review
- `POST /api/chat/send` - Send chat message
- `GET /api/chat/messages/:product_id` - Get chat messages

### System
- `GET /api/health` - Health check

## 🔒 Security Considerations

- All passwords are hashed using Werkzeug's security functions
- JWT tokens expire after 7 days
- Rate limiting prevents API abuse
- File uploads are validated and sanitized
- 2FA provides additional security layer
- Admin access is restricted and logged

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flask framework for the robust backend
- MongoDB for flexible data storage
- Open source community for various libraries used

## 📞 Support

For support, email support@renthub.com or create an issue in this repository.

---

**Note**: This is a demonstration project. For production use, ensure proper security measures, database backups, and monitoring are in place.
