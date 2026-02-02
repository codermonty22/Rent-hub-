//  Api configuration
const API_BASE_URL = "http://localhost:5000/api";
const IMAGE_BASE_URL = "http://localhost:5000";

// Rental type toggle
function switchRentalType(type) {
  const buttons = document.querySelectorAll(".toggle-btn");
  buttons.forEach((btn) => {
    btn.classList.remove("active");
    if (btn.textContent.toLowerCase().includes(type)) {
      btn.classList.add("active");
    }
  });

  const allProducts = document.querySelectorAll(".item-card");
  allProducts.forEach((product) => {
    const rentalType = product.getAttribute("data-rental-type");

    if (type === "short") {
      product.style.display = rentalType === "short" ? "block" : "none";
    } else {
      product.style.display = rentalType === "long" ? "block" : "none";
    }
  });

  if (window.innerWidth <= 768) {
    const productsSection = document.querySelector(".popular-items");
    if (productsSection) {
      productsSection.scrollIntoView({ behavior: "smooth" });
    }
  }
}

// API call function
async function apiCall(endpoint, options = {}) {
  const token = localStorage.getItem("token");
  const headers = {
    ...(options.headers || {}),
  };

  // Only add Authorization header if token exists and it's not a GET request to /products
  if (token && !(options.method === 'GET' && endpoint === '/products')) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (options.body instanceof FormData) {
    // Let the browser set the Content-Type header for multipart/form-data
    delete headers["Content-Type"];
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });
  if (!response.ok) {
    if (response.status === 401) {
      alert("Unauthorized access. Please log in.");
      window.location.href = "login.html";
    }
    const errorData = await response.json().catch(() => ({ message: `API call failed with status ${response.status}` }));
    throw new Error(errorData.message);
  }
  return response.json();
}

// Load products function for home page
async function loadProducts(filters = {}) {
  let queryParams = [];

  if (filters.category) queryParams.push(`category=${encodeURIComponent(filters.category)}`);
  if (filters.location) queryParams.push(`location=${encodeURIComponent(filters.location)}`);
  if (filters.min_price) queryParams.push(`min_price=${filters.min_price}`);
  if (filters.max_price) queryParams.push(`max_price=${filters.max_price}`);

  let endpoint = "/products";
  if (queryParams.length > 0) {
    endpoint += "?" + queryParams.join("&");
  }

  // Show loading state
  const grid = document.querySelector("#product-list") || document.querySelector(".item-grid");
  if (grid) {
    grid.innerHTML = `
      <div class="loading-spinner">
        <i class="fas fa-spinner fa-spin" style="font-size: 48px; margin-bottom: 20px;"></i>
        <h3>Loading products...</h3>
      </div>
    `;
  }

  try {
    const response = await apiCall(endpoint);
    let products = response.products || [];

    // Ensure products is an array
    if (!Array.isArray(products)) {
      products = [];
    }

    // Sort products if sortBy is specified
    if (filters.sortBy) {
      switch (filters.sortBy) {
        case 'name-asc':
          products.sort((a, b) => a.title.localeCompare(b.title));
          break;
        case 'name-desc':
          products.sort((a, b) => b.title.localeCompare(a.title));
          break;
        case 'price-asc':
          products.sort((a, b) => parseFloat(a.price) - parseFloat(b.price));
          break;
        case 'price-desc':
          products.sort((a, b) => parseFloat(b.price) - parseFloat(a.price));
          break;
        default:
          break;
      }
    }

    // Render
    const grid = document.querySelector("#product-list") || document.querySelector(".item-grid");
    if (!grid) return;

    grid.innerHTML = "";

    if (products.length === 0) {
      grid.innerHTML = `
        <div class="no-products">
          <i class="fas fa-search" style="font-size: 48px; margin-bottom: 20px;"></i>
          <h3>No products found</h3>
          <p>Try adjusting your search criteria or check back later.</p>
        </div>
      `;
      return;
    }

    products.forEach((p) => {
      const card = document.createElement("div");
      card.className = "item-card";
      card.setAttribute(
        "data-rental-type",
        p.rental_type === "day" || p.rental_type === "week" ? "short" : "long"
      );
      card.setAttribute("data-product-id", p._id);

      // Add rejected class if product is rejected
      if (p.status === 'rejected') {
        card.classList.add('rejected-product');
      }

      const imageUrl = p.images?.[0]
        ? (p.images[0].startsWith('http') ? p.images[0] : IMAGE_BASE_URL + '/' + p.images[0].replace(/^\/+/, ''))
        : "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=300&fit=crop";
      card.innerHTML = `
        <div class="item-image">
          <a href="product.html?id=${p._id}">
            <img src="${imageUrl}" alt="${p.title}">
          </a>
          <div class="item-badge">${p.category || 'New'}</div>
          <button class="wishlist-btn" onclick="event.preventDefault(); toggleWishlist('${p._id}')">
            <i class="far fa-heart"></i>
          </button>
          ${p.status === 'rejected' ? '<div class="rejected-overlay">Rejected</div>' : ''}
        </div>
        <div class="item-info">
          <div class="item-price">₹${p.price} <span>/${p.rental_type === 'day' ? 'day' : p.rental_type === 'week' ? 'week' : 'month'}</span></div>
          <h3 class="item-title"><a href="product.html?id=${p._id}">${p.title}</a></h3>
          <div class="item-location">
            <i class="fas fa-map-marker-alt"></i> ${p.location || 'Location not specified'}
          </div>
          <div class="item-owner">
            <div class="owner-avatar">
              <img src="https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=40&h=40&fit=crop&crop=face" alt="Owner">
            </div>
            <div class="owner-info">
              <h4>${p.owner_email ? p.owner_email.split('@')[0] : 'Owner'}</h4>
              <p>⭐ 4.8</p>
            </div>
          </div>
        </div>
      `;
      grid.appendChild(card);

      // Check wishlist status for this product
      checkWishlistStatus(p._id).then(isInWishlist => {
        updateWishlistButton(p._id, isInWishlist);
      });
    });
  } catch (e) {
    console.error("Failed to load products:", e);
    const grid = document.querySelector("#product-list") || document.querySelector(".item-grid");
    if (grid) {
      grid.innerHTML = `
        <div class="error-message">
          <i class="fas fa-exclamation-triangle" style="font-size: 48px; margin-bottom: 20px;"></i>
          <h3>Failed to load products</h3>
          <p>Please check your connection and try again.</p>
        </div>
      `;
    }
  }
}

function setupSearchForm() {
  const searchForm = document.querySelector('.search-bar');
  if (!searchForm) return;

  searchForm.onsubmit = (e) => {
    e.preventDefault();

    const searchInput = searchForm.querySelector('input[type="text"]');
    const categorySelect = searchForm.querySelector('select');
    const locationInput = searchForm.querySelector('input[placeholder="Location"]');

    const searchTerm = searchInput.value.trim();
    const category = categorySelect.value;
    const location = locationInput ? locationInput.value.trim() : '';

    loadProducts({
      category: category || '',
      location: location || '',
      searchTerm: searchTerm || ''
    });
  };
}

// Form handling functions
function isLoggedIn() {
  return localStorage.getItem("token") !== null;
}

function resetForm() {
  const listingForm = document.getElementById("listing-form");
  const photoPreview = document.getElementById("photoPreview");
  const formError = document.getElementById("formError");

  if (listingForm) listingForm.reset();
  if (photoPreview) photoPreview.innerHTML = "";
  if (formError) formError.style.display = "none";
}

// Photo preview
const itemPhotos = document.getElementById("item-photos");
const photoPreview = document.getElementById("photoPreview");
if (itemPhotos && photoPreview) {
  itemPhotos.onchange = () => {
    photoPreview.innerHTML = "";
    Array.from(itemPhotos.files)
      .slice(0, 8)
      .forEach((file) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          const img = document.createElement("img");
          img.src = e.target.result;
          photoPreview.appendChild(img);
        };
        reader.readAsDataURL(file);
      });
  };
}

// Form submission
const listingForm = document.getElementById("listing-form");
const formError = document.getElementById("formError");

if (listingForm) {
  listingForm.onsubmit = async (e) => {
    e.preventDefault();
    if (formError) formError.style.display = "none";

    if (!isLoggedIn()) {
      if (formError) {
        formError.textContent = "Please log in to add a listing.";
        formError.style.display = "block";
      }
      return;
    }

    const itemPhotosInput = document.getElementById("item-photos");
    if (itemPhotosInput && itemPhotosInput.files.length < 5) {
      if (formError) {
        formError.textContent = "Please upload at least 5 product photos.";
        formError.style.display = "block";
      }
      return;
    }

    const certInput = document.getElementById("item-cert");
    if (!certInput || !certInput.files[0]) {
      if (formError) {
        formError.textContent = "Please upload a product certification.";
        formError.style.display = "block";
      }
      return;
    }

    try {
      const formData = new FormData();
      formData.append("title", document.getElementById("item-name").value);
      formData.append("description", document.getElementById("item-description").value);
      formData.append("category", document.getElementById("item-category").value);
      formData.append("price", document.getElementById("item-price").value);
      formData.append("condition", document.getElementById("item-condition").value);
      formData.append(
        "rental_type",
        document.querySelector('input[name="rental-type"]:checked').value
      );
      formData.append("owner_email", document.getElementById("owner-email").value);
      formData.append("owner_phone", document.getElementById("owner-phone").value);
      formData.append("owner_address", document.getElementById("owner-address").value);
      formData.append("location", document.getElementById("owner-location").value);

      Array.from(itemPhotosInput.files).forEach((file) =>
        formData.append("images", file)
      );
      formData.append("cert", certInput.files[0]);

      const response = await apiCall("/products", {
        method: "POST",
        body: formData,
      });

      if (response.success) {
        alert("Listing submitted successfully! It will be reviewed by admin and appear on the homepage once approved.");
        const modal = document.getElementById("listing-modal");
        if (modal) modal.style.display = "none";
        resetForm();
        // Don't reload products immediately since it's pending approval
        // loadProducts();
      } else {
        throw new Error(response.message || "Failed to submit listing");
      }

    } catch (err) {
      console.error("Submit error:", err);
      if (formError) {
        formError.textContent = err.message || "Failed to submit listing. Please try again.";
        formError.style.display = "block";
      }
    }
  };
}

// Profile dropdown handling
function updateProfileDropdown() {
  const profileIcon = document.getElementById('profileIcon');
  const profileDropdown = document.getElementById('profileDropdown');

  if (!profileIcon || !profileDropdown) return;

  if (isLoggedIn()) {
    // Update profile icon to show user avatar (if available)
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    if (user.avatar) {
      profileIcon.src = user.avatar;
    } else {
      // Use a default user avatar
      profileIcon.src = 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=40&h=40&fit=crop&crop=face';
    }

    // Update dropdown to include profile link with click handler
    profileDropdown.innerHTML = `
      <a href="#" class="dropdown-item" onclick="navigateToProfile()">My Profile</a>
      <a href="#" onclick="logout()" class="dropdown-item">Logout</a>
    `;
  } else {
    // Default profile icon
    profileIcon.src = 'https://images.unsplash.com/photo-1494790108755-2616b612b47c?w=40&h=40&fit=crop&crop=face';

    // Default login/signup links
    profileDropdown.innerHTML = `
      <a href="login.html" class="dropdown-item">Login</a>
      <a href="signup.html" class="dropdown-item">Sign Up</a>
    `;
  }
}

function toggleProfileDropdown() {
  const profileDropdown = document.getElementById('profileDropdown');
  const profileContainer = document.getElementById('profileContainer');

  if (!profileDropdown || !profileContainer) return;

  // Toggle the 'show' class
  profileDropdown.classList.toggle('show');

  // Update aria-hidden attribute
  const isHidden = profileDropdown.classList.contains('show');
  profileDropdown.setAttribute('aria-hidden', !isHidden);
}

function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  updateProfileDropdown();
  // Redirect to home or refresh
  window.location.href = 'index.html';
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
  const profileContainer = document.getElementById('profileContainer');
  const profileDropdown = document.getElementById('profileDropdown');

  if (!profileContainer || !profileDropdown) return;

  if (!profileContainer.contains(event.target)) {
    profileDropdown.classList.remove('show');
    profileDropdown.setAttribute('aria-hidden', 'true');
  }
});

// Add click event to profile container
document.addEventListener('DOMContentLoaded', function() {
  const profileContainer = document.getElementById('profileContainer');
  if (profileContainer) {
    profileContainer.addEventListener('click', function(event) {
      event.preventDefault();
      toggleProfileDropdown();
    });
  }
});

function navigateToProfile() {
  window.location.href = 'profile.html';
}

function filterByCategory(category) {
  // Update URL without page reload
  const url = new URL(window.location);
  url.searchParams.set('category', category);
  window.history.pushState({}, '', url);

  // Load filtered products
  loadProducts({ category });

  // Scroll to products section
  const popularSection = document.querySelector(".popular-items");
  if (popularSection) {
    popularSection.scrollIntoView({ behavior: "smooth" });
  }
}

// Add click event listeners to category cards
document.addEventListener('DOMContentLoaded', () => {
  const categoryCards = document.querySelectorAll('.category-card[data-category]');
  categoryCards.forEach(card => {
    card.addEventListener('click', (e) => {
      e.preventDefault();
      const category = card.getAttribute('data-category');
      if (category) {
        filterByCategory(category);
      }
    });
  });
});

// Search bar enhancements
function selectSuggestion(suggestion) {
  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.value = suggestion;
    hideTrendingSuggestions();
  }
}

function showTrendingSuggestions() {
  const suggestions = document.getElementById('trendingSuggestions');
  if (suggestions) {
    suggestions.style.display = 'block';
  }
}

function hideTrendingSuggestions() {
  const suggestions = document.getElementById('trendingSuggestions');
  if (suggestions) {
    suggestions.style.display = 'none';
  }
}

// Enhanced search form setup
function setupSearchForm() {
  const searchForm = document.querySelector('.search-bar');
  const searchInput = document.getElementById('searchInput');

  if (!searchForm) return;

  // Show trending suggestions when search input is focused
  if (searchInput) {
    searchInput.addEventListener('focus', showTrendingSuggestions);
    searchInput.addEventListener('blur', () => {
      // Delay hiding to allow clicking on suggestions
      setTimeout(hideTrendingSuggestions, 150);
    });
  }

  searchForm.onsubmit = (e) => {
    e.preventDefault();

    const searchTerm = searchInput ? searchInput.value.trim() : '';
    const categorySelect = document.getElementById('categorySelect');
    const priceSelect = document.getElementById('priceSelect');
    const locationInput = document.getElementById('locationInput');

    const category = categorySelect ? categorySelect.value : '';
    const priceRange = priceSelect ? priceSelect.value : '';
    const location = locationInput ? locationInput.value.trim() : '';

    loadProducts({
      category: category || '',
      location: location || '',
      searchTerm: searchTerm || ''
    });

    // Scroll to products section
    const popularSection = document.querySelector(".popular-items");
    if (popularSection) {
      popularSection.scrollIntoView({ behavior: "smooth" });
    }
  };
}

// Categories Carousel Functionality
class CategoriesCarousel {
  constructor() {
    this.carousel = document.querySelector('.categories-carousel');
    if (!this.carousel) return;

    this.track = this.carousel.querySelector('.carousel-track');
    this.slides = this.carousel.querySelectorAll('.category-card');
    this.prevBtn = this.carousel.querySelector('.carousel-prev');
    this.nextBtn = this.carousel.querySelector('.carousel-next');
    this.dotsContainer = this.carousel.querySelector('.carousel-dots');

    this.currentIndex = 0;
    this.slidesPerView = this.getSlidesPerView();
    this.totalSlides = this.slides.length;
    this.maxIndex = Math.max(0, this.totalSlides - this.slidesPerView);

    this.init();
  }

  init() {
    if (!this.track || this.slides.length === 0) return;

    this.createDots();
    this.updateCarousel();
    this.bindEvents();
    this.startAutoPlay();
  }

  getSlidesPerView() {
    if (window.innerWidth >= 1024) return 4;
    if (window.innerWidth >= 768) return 3;
    if (window.innerWidth >= 480) return 2;
    return 1;
  }

  createDots() {
    if (!this.dotsContainer) return;

    this.dotsContainer.innerHTML = '';
    const totalDots = Math.ceil(this.totalSlides / this.slidesPerView);

    for (let i = 0; i < totalDots; i++) {
      const dot = document.createElement('div');
      dot.className = 'carousel-dot';
      if (i === 0) dot.classList.add('active');
      dot.addEventListener('click', () => this.goToSlide(i));
      this.dotsContainer.appendChild(dot);
    }
  }

  updateCarousel() {
    if (!this.track) return;

    const translateX = -this.currentIndex * (100 / this.slidesPerView);
    this.track.style.transform = `translateX(${translateX}%)`;

    // Update dots
    const dots = this.dotsContainer?.querySelectorAll('.carousel-dot');
    dots?.forEach((dot, index) => {
      dot.classList.toggle('active', index === this.currentIndex);
    });

    // Update button states
    if (this.prevBtn) {
      this.prevBtn.style.opacity = this.currentIndex === 0 ? '0.5' : '1';
      this.prevBtn.style.pointerEvents = this.currentIndex === 0 ? 'none' : 'auto';
    }

    if (this.nextBtn) {
      this.nextBtn.style.opacity = this.currentIndex >= this.maxIndex ? '0.5' : '1';
      this.nextBtn.style.pointerEvents = this.currentIndex >= this.maxIndex ? 'none' : 'auto';
    }
  }

  nextSlide() {
    if (this.currentIndex < this.maxIndex) {
      this.currentIndex++;
      this.updateCarousel();
    }
  }

  prevSlide() {
    if (this.currentIndex > 0) {
      this.currentIndex--;
      this.updateCarousel();
    }
  }

  goToSlide(index) {
    this.currentIndex = Math.min(Math.max(index, 0), this.maxIndex);
    this.updateCarousel();
  }

  bindEvents() {
    // Navigation buttons
    if (this.prevBtn) {
      this.prevBtn.addEventListener('click', () => this.prevSlide());
    }

    if (this.nextBtn) {
      this.nextBtn.addEventListener('click', () => this.nextSlide());
    }

    // Touch/swipe support
    let startX = 0;
    let isDragging = false;

    this.track.addEventListener('touchstart', (e) => {
      startX = e.touches[0].clientX;
      isDragging = true;
    });

    this.track.addEventListener('touchmove', (e) => {
      if (!isDragging) return;
      e.preventDefault();
    });

    this.track.addEventListener('touchend', (e) => {
      if (!isDragging) return;
      isDragging = false;

      const endX = e.changedTouches[0].clientX;
      const diffX = startX - endX;

      if (Math.abs(diffX) > 50) {
        if (diffX > 0) {
          this.nextSlide();
        } else {
          this.prevSlide();
        }
      }
    });

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowLeft') {
        this.prevSlide();
      } else if (e.key === 'ArrowRight') {
        this.nextSlide();
      }
    });

    // Window resize
    window.addEventListener('resize', () => {
      const newSlidesPerView = this.getSlidesPerView();
      if (newSlidesPerView !== this.slidesPerView) {
        this.slidesPerView = newSlidesPerView;
        this.maxIndex = Math.max(0, this.totalSlides - this.slidesPerView);
        this.currentIndex = Math.min(this.currentIndex, this.maxIndex);
        this.createDots();
        this.updateCarousel();
      }
    });
  }

  startAutoPlay() {
    setInterval(() => {
      if (this.currentIndex >= this.maxIndex) {
        this.currentIndex = 0;
      } else {
        this.currentIndex++;
      }
      this.updateCarousel();
    }, 5000); // Auto-advance every 5 seconds
  }
}

// Initialize everything on page load
document.addEventListener('DOMContentLoaded', () => {
  // Check for category in URL parameters and load filtered products
  const urlParams = new URLSearchParams(window.location.search);
  const categoryFromUrl = urlParams.get('category');

  setupSearchForm();
  updateProfileDropdown();
  updateCartCount(); // Update cart count on page load

  // Initialize categories carousel
  new CategoriesCarousel();

  // Add event listeners for listing modal
  const addListingBtn = document.getElementById('add-listing-btn');
  const ctaAddListingBtn = document.getElementById('cta-add-listing-btn');
  const listingModal = document.getElementById('listing-modal');

  if (addListingBtn && listingModal) {
    addListingBtn.addEventListener('click', (e) => {
      e.preventDefault();
      listingModal.style.display = 'block';
    });
  }

  if (ctaAddListingBtn && listingModal) {
    ctaAddListingBtn.addEventListener('click', (e) => {
      e.preventDefault();
      listingModal.style.display = 'block';
    });
  }

  // Products page specific
  if (document.getElementById('product-list')) {
    // On products.html
    const initialFilters = {
      category: categoryFromUrl || '',
    };
    loadProducts(initialFilters);

    // Update page title and category title
    if (categoryFromUrl) {
      const pageTitle = document.getElementById('page-title');
      const categoryTitle = document.getElementById('category-title');
      if (pageTitle) {
        pageTitle.textContent = `${categoryFromUrl.charAt(0).toUpperCase() + categoryFromUrl.slice(1)} Products - RentHuB`;
      }
      if (categoryTitle) {
        categoryTitle.textContent = categoryFromUrl.charAt(0).toUpperCase() + categoryFromUrl.slice(1);
      }
    }

    // Event listeners
    const searchInput = document.getElementById('search-input');
    const sortBy = document.getElementById('sort-by');
    const filterBy = document.getElementById('filter-by');

    let currentFilters = { ...initialFilters };

    searchInput.addEventListener('input', (e) => {
      currentFilters.searchTerm = e.target.value;
      loadProducts(currentFilters);
    });

    sortBy.addEventListener('change', (e) => {
      currentFilters.sortBy = e.target.value;
      loadProducts(currentFilters);
    });

    filterBy.addEventListener('change', (e) => {
      currentFilters.category = e.target.value === 'all' ? '' : e.target.value;
      loadProducts(currentFilters);
    });
  } else {
    // On index.html
    loadProducts({ category: categoryFromUrl || '' });
  }
});

// Handle listing modal close button
document.addEventListener('DOMContentLoaded', () => {
  const closeBtn = document.getElementById('closeListingModalBtn');
  const modal = document.getElementById('listing-modal');

  if (closeBtn && modal) {
    closeBtn.addEventListener('click', () => {
      modal.style.display = 'none';
    });
  }

  // Close modal when clicking outside
  window.addEventListener('click', (event) => {
    if (event.target === modal) {
      modal.style.display = 'none';
    }
  });
});

// Testimonials slider functionality
let currentTestimonial = 0;
const testimonials = document.querySelectorAll('.testimonial-card');

function showTestimonial(index) {
  if (!testimonials.length) return;

  testimonials.forEach((testimonial, i) => {
    testimonial.classList.remove('active');
    if (i === index) {
      testimonial.classList.add('active');
    }
  });

  // Update dots
  const dots = document.querySelectorAll('.testimonial-dots .dot');
  dots.forEach((dot, i) => {
    dot.classList.remove('active');
    if (i === index) {
      dot.classList.add('active');
    }
  });

  currentTestimonial = index;
}

function nextTestimonial() {
  const nextIndex = (currentTestimonial + 1) % testimonials.length;
  showTestimonial(nextIndex);
}

function prevTestimonial() {
  const prevIndex = (currentTestimonial - 1 + testimonials.length) % testimonials.length;
  showTestimonial(prevIndex);
}

function goToTestimonial(index) {
  showTestimonial(index);
}

// Auto-play testimonials
function startTestimonialAutoPlay() {
  setInterval(() => {
    nextTestimonial();
  }, 5000); // Change testimonial every 5 seconds
}

// Initialize testimonials on page load
document.addEventListener('DOMContentLoaded', () => {
  if (testimonials.length > 0) {
    showTestimonial(0);
    startTestimonialAutoPlay();
  }
});

// Handle browser navigation (back/forward buttons)
window.addEventListener('popstate', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const categoryFromUrl = urlParams.get('category');
  loadProducts({ category: categoryFromUrl || '' });
});




// Function to show/hide the loading spinner
function showLoadingSpinner() {
    document.getElementById('loadingSpinner').style.display = 'block';
    document.getElementById('productContent').classList.add('loading');
    document.getElementById('reviewsList').classList.add('loading');
}

function hideLoadingSpinner() {
    document.getElementById('loadingSpinner').style.display = 'none';
    document.getElementById('productContent').classList.remove('loading');
    document.getElementById('reviewsList').classList.remove('loading');
}

// Function to fetch product data from backend API
async function fetchProductData() {
    try {
        // Get product ID from URL query parameter
        const urlParams = new URLSearchParams(window.location.search);
        const productId = urlParams.get('id');

        if (!productId) {
            showToast('Product ID not found in URL.', 'error');
            hideLoadingSpinner();
            return;
        }

        // Fetch the specific product from API
        const response = await apiCall(`/products/${productId}`);
        const product = response.product;

        if (!product) {
            showToast('Product not found.', 'error');
            hideLoadingSpinner();
            return;
        }

        // Fetch reviews for this product
        let reviews = [];
        try {
            const reviewsResponse = await apiCall(`/reviews/${productId}`);
            reviews = reviewsResponse.reviews || [];
        } catch (error) {
            console.warn('Failed to fetch reviews:', error);
            reviews = [];
        }

        // Transform backend data to UI format
        const uiProduct = {
            id: product._id,
            title: product.title,
            badge: product.category,
            location: product.location,
            owner: {
                name: product.owner_email ? product.owner_email.split('@')[0] : 'Owner',
                rating: product.rating || 4.8, // Use backend rating if available
                rentals: product.totalRatings || 0, // Use backend total ratings
                avatarInitials: product.owner_email ? product.owner_email.charAt(0).toUpperCase() : 'O'
            },
            price: product.price,
            originalPrice: null, // Backend doesn't have original price
            description: product.description,
            images: product.images ? product.images.map(img => IMAGE_BASE_URL + img) : [],
            rentalType: product.rental_type,
            condition: product.condition,
            reviews: reviews // Now includes actual reviews from backend
        };

        updateUI(uiProduct);
    } catch (error) {
        console.error('Error fetching product data:', error);
        showToast('Failed to load product data. Please try again.', 'error');
        hideLoadingSpinner();
    }
}

// Function to update the UI with product data
function updateUI(product) {
    document.getElementById('productTitle').textContent = product.title;
    document.getElementById('productBadge').textContent = product.badge;
    document.getElementById('breadcrumbCategory').textContent = product.badge;
    document.getElementById('breadcrumbProduct').textContent = product.title;

    // Set main image
    const mainImage = document.getElementById('mainImage');
    if (product.images.length > 0) {
        mainImage.src = product.images[0];
    } else {
        mainImage.src = "https://via.placeholder.com/500x500?text=No+Image";
    }

    // Update price display with rental type
    const priceUnit = product.rentalType === 'day' ? '/day' : product.rentalType === 'week' ? '/week' : '/month';
    document.getElementById('currentPrice').innerHTML = `₹${product.price} <span class="price-per-unit">${priceUnit}</span>`;

    // Handle original price and discount (if available)
    const originalPriceEl = document.getElementById('originalPrice');
    const discountEl = document.getElementById('discount');
    if (product.originalPrice && product.originalPrice > product.price) {
        originalPriceEl.textContent = `₹${product.originalPrice}`;
        originalPriceEl.style.display = 'inline';
        const discountPercent = Math.round(((product.originalPrice - product.price) / product.originalPrice) * 100);
        discountEl.textContent = `${discountPercent}% OFF`;
        discountEl.style.display = 'inline';
    } else {
        originalPriceEl.style.display = 'none';
        discountEl.style.display = 'none';
    }

    document.getElementById('productDescription').textContent = product.description;

    // Update owner info
    document.getElementById('ownerAvatar').textContent = product.owner.avatarInitials;
    document.getElementById('ownerName').textContent = product.owner.name;
    document.getElementById('ownerLocation').textContent = product.location;

    // Update rental terms
    const rentalTermsEl = document.getElementById('rentalTerms');
    if (rentalTermsEl) {
        rentalTermsEl.textContent = `Minimum rental period: 1 ${product.rentalType}. Security deposit may apply.`;
    }

    // Render image thumbnails
    const thumbnailsContainer = document.getElementById('thumbnails');
    thumbnailsContainer.innerHTML = '';
    product.images.forEach((imgSrc, index) => {
        const thumbnailDiv = document.createElement('div');
        thumbnailDiv.classList.add('thumbnail');
        if (index === 0) {
            thumbnailDiv.classList.add('active');
        }
        thumbnailDiv.innerHTML = `<img src="${imgSrc}" alt="Product Thumbnail ${index + 1}">`;
        thumbnailDiv.addEventListener('click', () => {
            document.getElementById('mainImage').src = imgSrc;
            document.querySelectorAll('.thumbnail').forEach(t => t.classList.remove('active'));
            thumbnailDiv.classList.add('active');
        });
        thumbnailsContainer.appendChild(thumbnailDiv);
    });

    // Render reviews
    renderReviews(product.reviews);

    // Hide loading spinner after UI is updated
    hideLoadingSpinner();
}

// Function to render reviews and update rating summary
function renderReviews(reviews) {
    const reviewsList = document.getElementById('reviewsList');
    reviewsList.innerHTML = ''; // Clear existing reviews

    if (reviews.length === 0) {
        reviewsList.innerHTML = `<p class="no-reviews">No reviews yet. Be the first to leave one!</p>`;
        document.getElementById('reviewCount').textContent = '0';
        document.getElementById('overallRating').textContent = 'N/A';
        document.getElementById('productStars').innerHTML = `<span class="star empty">★</span><span class="star empty">★</span><span class="star empty">★</span><span class="star empty">★</span><span class="star empty">★</span>`;
        return;
    }

    let totalRating = 0;
    const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };

    reviews.forEach(review => {
        totalRating += review.rating;
        ratingCounts[review.rating]++;

        const reviewElement = document.createElement('div');
        reviewElement.classList.add('review-item');
        reviewElement.innerHTML = `
            <div class="review-header">
                <div class="reviewer-info">
                    <div class="reviewer-avatar">${review.name.split(' ').map(n => n[0]).join('')}</div>
                    <div class="reviewer-details">
                        <h5>${review.name}</h5>
                        <div class="review-date">${review.date}</div>
                    </div>
                </div>
                <div class="review-rating">
                    ${'★'.repeat(review.rating)}${'★'.repeat(5 - review.rating).replace(/★/g, '<span class="empty">★</span>')}
                </div>
            </div>
            <div class="review-content">${review.content}</div>
        `;
        reviewsList.appendChild(reviewElement);
    });

    // Update overall rating and breakdown
    const averageRating = totalRating / reviews.length;
    document.getElementById('overallRating').textContent = averageRating.toFixed(1);
    document.getElementById('reviewCount').textContent = reviews.length;

    const productStars = document.getElementById('productStars');
    productStars.innerHTML = '';
    const roundedRating = Math.round(averageRating);
    for (let i = 0; i < 5; i++) {
        const star = document.createElement('span');
        star.classList.add('star');
        if (i >= roundedRating) {
            star.classList.add('empty');
        }
        star.innerHTML = '★';
        productStars.appendChild(star);
    }
    
    // Update rating breakdown bars
    document.querySelectorAll('.rating-bar-fill').forEach((bar, index) => {
        const rating = 5 - index;
        const percentage = (ratingCounts[rating] / reviews.length) * 100;
        bar.querySelector('.rating-fill').style.width = `${percentage}%`;
        bar.nextElementSibling.textContent = `${Math.round(percentage)}%`;
    });
}

// Function to handle rental duration selection
function selectDuration(element) {
    document.querySelectorAll('.duration-option').forEach(el => el.classList.remove('selected'));
    element.classList.add('selected');
}

// Function to add product to cart (or initiate rental process)
async function addToCart() {
    const selectedDuration = document.querySelector('.duration-option.selected');
    if (!selectedDuration) {
        showToast('Please select a rental duration.', 'error');
        return;
    }
    const duration = selectedDuration.dataset.duration;
    const unit = selectedDuration.dataset.unit;

    // Get product ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');

    if (!productId) {
        showToast('Product ID not found.', 'error');
        return;
    }

    try {
        if (isLoggedIn()) {
            await apiCall('/cart/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    product_id: productId,
                    quantity: 1,
                    duration: duration,
                    unit: unit
                })
            });
        } else {
            // For guest users, use localStorage
            let cart = JSON.parse(localStorage.getItem('guestCart') || '[]');
            const existingItem = cart.find(item =>
                item.product_id === productId &&
                item.duration === duration &&
                item.unit === unit
            );

            if (existingItem) {
                existingItem.quantity += 1;
            } else {
                cart.push({
                    product_id: productId,
                    quantity: 1,
                    duration: duration,
                    unit: unit,
                    added_at: new Date().toISOString()
                });
            }

            localStorage.setItem('guestCart', JSON.stringify(cart));
        }

        // Update cart count
        updateCartCount();

        showToast(`Added to cart for a ${duration} ${unit} rental!`, 'success');
    } catch (error) {
        console.error('Error adding to cart:', error);
        showToast('Failed to add item to cart', 'error');
    }
}

// Function to handle star rating selection in the modal
function selectRating(rating) {
    const stars = document.querySelectorAll('#ratingInput .rating-star');
    stars.forEach((star, index) => {
        if (index < rating) {
            star.classList.add('active');
        } else {
            star.classList.remove('active');
        }
    });
}

// Function to submit a review from the modal
async function submitReview(event) {
    event.preventDefault();
    const name = document.getElementById('reviewerName').value;
    const title = document.getElementById('reviewTitle').value;
    const content = document.getElementById('reviewContent').value;
    const rating = document.querySelectorAll('.rating-star.active').length;

    if (rating === 0) {
        showToast('Please select a rating.', 'error');
        return;
    }

    if (!isLoggedIn()) {
        showToast('Please log in to submit a review.', 'error');
        return;
    }

    // Get product ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');

    if (!productId) {
        showToast('Product ID not found.', 'error');
        return;
    }

    try {
        const response = await apiCall('/reviews', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                product_id: productId,
                rating: rating,
                title: title,
                comment: content
            })
        });

        if (response.success) {
            showToast('Your review has been submitted!', 'success');
            closeReviewModal();
            // Refresh the product data to show the new review
            fetchProductData();
        } else {
            showToast(response.message || 'Failed to submit review.', 'error');
        }
    } catch (error) {
        console.error('Error submitting review:', error);
        showToast('Failed to submit review. Please try again.', 'error');
    }
}

// Functions to open and close modals
function openImageModal() {
    document.getElementById('modalImage').src = document.getElementById('mainImage').src;
    document.getElementById('imageModal').style.display = 'flex';
}

function closeImageModal() {
    document.getElementById('imageModal').style.display = 'none';
}

function openReviewModal() {
    document.getElementById('reviewModal').style.display = 'flex';
}

function closeReviewModal() {
    document.getElementById('reviewModal').style.display = 'none';
}

const predefinedResponses = {
    // Greetings
    "hello": "Hi! 👋 Welcome to RentHuB! How can I help you today?",
    "hi": "Hello! 👋 I'm here to help you with anything related to RentHuB!",
    "hey": "Hey there! 😊 What can I assist you with today?",
    "good morning": "Good morning! ☀️ Ready to explore some amazing rental items?",
    "good afternoon": "Good afternoon! 🌞 How can I help you find what you need?",
    "good evening": "Good evening! 🌙 Need help with rentals or listings?",

    // About RentHuB
    "what is renthub": "RentHuB is India's leading peer-to-peer rental marketplace! 🏠 We connect people who want to rent items with those who have items to share. From furniture to electronics, cars to fashion - you can rent almost anything!",
    "how does renthub work": "It's simple! 🎯 Browse items → Choose rental duration → Add to cart → Complete secure payment → Pick up your rental. Owners list items, renters find what they need!",
    "what can i rent": "You can rent almost anything! 🛋️ Furniture, 🚗 Cars, 💻 Electronics, 📱 Mobiles, 🐕 Pets, 👕 Fashion, 📚 Books & Sports, 🔧 Services, and more!",
    "is it safe": "Absolutely! 🔒 All users are verified, payments are secure, items are inspected, and we have a dispute resolution system. Your safety is our priority!",

    // User Registration & Login
    "how do i sign up": "Click the profile icon (👤) in the top right → Select 'Sign Up' → Fill in your details → Verify your email. It's quick and free! 📝",
    "how do i login": "Click the profile icon (👤) → Select 'Login' → Enter your email and password. Forgot password? Click 'Forgot Password' to reset it.",
    "forgot password": "No worries! On the login page, click 'Forgot Password' → Enter your email → Check your inbox for reset instructions.",
    "verify account": "After signup, check your email for a verification link. Click it to activate your account and start renting!",

    // Browsing & Searching
    "how do i search": "Use the search bar at the top! 🔍 Type what you're looking for, select category, set price range, and enter location. We also show trending suggestions!",
    "categories": "We have 9 main categories: 🪑 Furniture, 🚗 Cars, 🏠 Properties, 📱 Mobiles, 📺 Electronics, 🐕 Pets, 👕 Fashion, 📚 Books & Sports, 🔧 Services",
    "filter products": "Use the filter options: category, price range, location, and premium only. You can also sort by name or price!",
    "trending items": "Check the 'Popular Items' section on our homepage for the most rented items in your area!",

    // Renting Process
    "how do i rent an item": "Browse products → Click on an item → Select rental duration → Add to cart → Complete payment → Contact owner for pickup. Easy! 🛒",
    "rental duration": "Choose from daily, weekly, or monthly rentals depending on the item. Prices vary by duration!",
    "payment methods": "We accept all major credit/debit cards, UPI, net banking, and digital wallets. All payments are 100% secure! 💳",
    "security deposit": "Some items require a security deposit (refundable). It's mentioned in the item details. Always get a receipt!",
    "pickup delivery": "Coordinate pickup/delivery directly with the owner. We recommend meeting in public places for safety.",
    "return item": "Return the item on time to the agreed location. Take photos as proof. Your deposit will be refunded within 3-5 business days.",

    // Listing Items
    "how do i list an item": "Login → Click 'Add Listing' → Fill details (title, description, price, category) → Upload 5+ photos → Add certification → Submit for approval. 📤",
    "listing requirements": "You need: 5+ clear photos, product description, fair price, valid certification document, and accurate location. All listings are reviewed before approval.",
    "pricing tips": "Research similar items first. Consider your costs (maintenance, insurance) and set competitive prices. You can change prices anytime!",
    "certification": "Upload product certification (bill/receipt) as PDF or image. This builds trust with renters. Required for all listings!",
    "listing approval": "Our team reviews listings within 24 hours. You'll get an email notification. Most listings are approved if they meet our guidelines.",

    // Premium Membership
    "premium membership": "Unlock amazing benefits! ⭐ Unlimited listings, priority placement, advanced analytics, 24/7 support, and lower commission rates!",
    "how do i become premium": "Scroll to 'Premium Membership' section → Choose Basic/Elite/Elite plan → Complete payment. Instant activation! 💎",
    "premium benefits": "Premium members get: unlimited listings, featured placement, detailed analytics, dedicated support, and commissions as low as 1%!",
    "premium pricing": "Basic: ₹299/month, Premium: ₹599/month, Elite: ₹999/month. Cancel anytime, no hidden fees!",
    "commission rates": "Free members: 5% commission. Premium: 3%, Elite: 1%. You keep more money from your rentals! 💰",

    // Cart & Checkout
    "add to cart": "Click any item → Select duration → Click 'Add to Cart'. You can add multiple items and checkout together!",
    "view cart": "Click the cart icon in the header to see your items, quantities, and total cost.",
    "checkout process": "Review cart → Enter delivery details → Select payment method → Complete payment. You'll get confirmation instantly!",
    "modify cart": "In your cart, you can change quantities, remove items, or update rental durations before checkout.",

    // Reviews & Ratings
    "leave review": "After rental completion, go to the product page → Scroll to reviews → Click 'Write Review' → Rate 1-5 stars and share your experience.",
    "reviews helpful": "Reviews help others make informed decisions. Be honest, detailed, and respectful. Your feedback matters! ⭐",

    // Wishlist
    "wishlist": "Click the heart icon (❤️) on any item to add to wishlist. Access it from your profile. Never lose track of items you love!",
    "how to use wishlist": "Browse items → Click heart icon to save → Go to profile → View wishlist. Perfect for planning future rentals!",

    // Profile Management
    "edit profile": "Login → Click profile icon → 'My Profile' → Update personal info, add photo, change password, view rental history.",
    "rental history": "Check your profile for past rentals, earnings (if owner), reviews received, and account activity.",
    "change password": "Profile → Account Settings → Change Password. Use a strong password with uppercase, lowercase, numbers, and symbols.",
    "delete account": "Profile → Account Settings → Deactivate Account. This permanently removes your data. Contact support if needed.",

    // Admin Features
    "admin login": "For administrators: Use email admin@renthub.com and password admin123 to access the admin panel.",
    "admin features": "Admins can: approve/reject listings, view all users, manage products, clear data, view analytics, and moderate content.",
    "approve products": "Admin Panel → Products tab → Find pending items → Click 'Approve' or 'Reject' with reason.",
    "view users": "Admin Panel → Users tab → See all registered users, their status, join date, and activity metrics.",
    "clear products": "Admin Panel → Products → 'Clear All Products' button. ⚠️ This permanently deletes all products. Use carefully!",

    // Technical Support
    "contact support": "Email: support@renthub.com, Phone: 1800-XXX-XXXX, or use this chat! We're here 24/7 for premium members.",
    "report problem": "Use the contact form or email support@renthub.com with details. Include screenshots if possible.",
    "bug report": "Found a bug? Email support@renthub.com with: what you were doing, what happened, browser/device info.",

    // Legal & Safety
    "terms of service": "Read our complete terms at renthub.com/terms. Covers user responsibilities, payments, disputes, and platform rules.",
    "privacy policy": "Your privacy matters! We protect your data and never share personal info. Read full policy at renthub.com/privacy.",
    "refund policy": "Refunds processed within 3-5 business days for cancellations. Security deposits refunded after item return inspection.",
    "dispute resolution": "Contact both parties first. If unresolved, contact our support team. We mediate fairly and protect both sides.",

    // Advanced Features
    "location search": "Enter your city/area in the search bar. We'll show items available near you with pickup/delivery options.",
    "price range": "Use the price filter: ₹0-499, ₹500-999, ₹1000-4999, or ₹5000+. Find items within your budget!",
    "premium only": "Check 'Premium Only' to see listings from verified premium sellers with better support and faster approval.",
    "short term vs long term": "Toggle between Short Term (daily/weekly) and Long Term (monthly) rentals using buttons in the header.",

    // Earnings & Business
    "how much can i earn": "Depends on your items and location! Popular items can earn ₹500-5000+ per month. Premium listings get more visibility!",
    "earnings tracking": "Premium members get detailed analytics: views, bookings, earnings reports, and performance insights.",
    "taxes": "You're responsible for any applicable taxes on earnings. Keep records for tax purposes. Consult a tax advisor.",
    "multiple listings": "Premium members can list unlimited items. Free members limited to 10. More listings = more earning potential!",

    // Mobile & Accessibility
    "mobile app": "We're working on a mobile app! For now, our website is fully responsive and works great on all devices.",
    "browser compatibility": "Works best on Chrome, Firefox, Safari, and Edge. Clear cache if you experience issues.",

    // Default responses
    "default": "I'm not sure about that specific question. Try asking about: renting items, listing products, premium membership, payments, or account help. Or contact support@renthub.com for detailed assistance!",
    "sorry": "No need to apologize! 😊 I'm here to help. What can I assist you with regarding RentHuB?",
    "thank you": "You're very welcome! 😊 Happy renting on RentHuB! If you need anything else, just ask.",
    "thanks": "My pleasure! 🎉 Enjoy using RentHuB. Feel free to ask if you have more questions!"
};

// Chat widget functions
async function toggleChat() {
    const chatWindow = document.getElementById('chatWindow');
    const chatMessages = document.getElementById('chatMessages');

    if (chatWindow.style.display === 'flex') {
        chatWindow.style.display = 'none';
    } else {
        chatWindow.style.display = 'flex';

        // Load existing messages if empty
        if (chatMessages && chatMessages.children.length === 0) {
            await loadChatMessages();
        }

        document.getElementById('chatInput').focus();
    }
}

function closeChat() {
    document.getElementById('chatWindow').style.display = 'none';
}

function clearChat() {
    const chatMessages = document.getElementById('chatMessages');
    if (chatMessages) {
        chatMessages.innerHTML = '';
    }
}

async function sendMessage() {
    const chatInput = document.getElementById('chatInput');
    const chatMessages = document.getElementById('chatMessages');
    const message = chatInput.value.trim();
    if (message === '') return;

    if (!isLoggedIn()) {
        showToast('Please log in to send messages.', 'error');
        return;
    }

    // Get product ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');
    if (!productId) {
        showToast('Product ID not found.', 'error');
        return;
    }

    // Append user message immediately
    const userMessageElement = document.createElement('div');
    userMessageElement.classList.add('chat-message', 'sent');
    userMessageElement.innerHTML = `<strong>You:</strong> ${message}`;
    chatMessages.appendChild(userMessageElement);

    chatInput.value = '';
    chatMessages.scrollTop = chatMessages.scrollHeight;

    try {
        // Send message to backend
        const response = await apiCall('/chat/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                product_id: productId,
                message: message
            })
        });

        if (response.success) {
            // Message sent successfully
            console.log('Message sent successfully');
        } else {
            showToast(response.message || 'Failed to send message.', 'error');
        }
    } catch (error) {
        console.error('Error sending message:', error);
        showToast('Failed to send message. Please try again.', 'error');
    }
}

function handleChatKeyPress(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendMessage();
    }
}

function openChat() {
    toggleChat();
}

async function loadChatMessages() {
    if (!isLoggedIn()) {
        return;
    }

    // Get product ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');
    if (!productId) {
        return;
    }

    try {
        const response = await apiCall(`/chat/messages/${productId}`);
        const messages = response.messages || [];

        const chatMessages = document.getElementById('chatMessages');
        if (!chatMessages) return;

        // Clear existing messages
        chatMessages.innerHTML = '';

        // Add messages
        messages.forEach(msg => {
            const messageElement = document.createElement('div');
            messageElement.classList.add('chat-message');

            // Check if message is from current user
            const currentUser = JSON.parse(localStorage.getItem('user') || '{}');
            const isCurrentUser = msg.sender_id === currentUser.id;

            messageElement.classList.add(isCurrentUser ? 'sent' : 'received');
            messageElement.innerHTML = `<strong>${isCurrentUser ? 'You' : msg.sender_name}:</strong> ${msg.message}`;
            chatMessages.appendChild(messageElement);
        });

        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;

    } catch (error) {
        console.error('Error loading chat messages:', error);
    }
}

function getBotResponse(userMessage) {
    // Convert to lowercase for case-insensitive matching
    const message = userMessage.toLowerCase().trim();

    // Check for exact matches first
    if (predefinedResponses[message]) {
        return predefinedResponses[message];
    }

    // Check for partial matches (keywords within the message)
    for (const key in predefinedResponses) {
        if (key !== "default" && message.includes(key)) {
            return predefinedResponses[key];
        }
    }

    // Special handling for common variations
    if (message.includes("sign up") || message.includes("register") || message.includes("create account")) {
        return predefinedResponses["how do i sign up"];
    }

    if (message.includes("log in") || message.includes("login") || message.includes("sign in")) {
        return predefinedResponses["how do i login"];
    }

    if (message.includes("premium") && (message.includes("become") || message.includes("join") || message.includes("upgrade"))) {
        return predefinedResponses["how do i become premium"];
    }

    if (message.includes("rent") && (message.includes("how") || message.includes("process") || message.includes("work"))) {
        return predefinedResponses["how do i rent an item"];
    }

    if (message.includes("list") && (message.includes("how") || message.includes("add") || message.includes("create"))) {
        return predefinedResponses["how do i list an item"];
    }

    if (message.includes("cart") || message.includes("checkout")) {
        return predefinedResponses["checkout process"];
    }

    if (message.includes("payment") || message.includes("pay")) {
        return predefinedResponses["payment methods"];
    }

    if (message.includes("support") || message.includes("help") || message.includes("contact")) {
        return predefinedResponses["contact support"];
    }

    if (message.includes("admin") && message.includes("login")) {
        return predefinedResponses["admin login"];
    }

    // Default response
    return predefinedResponses["default"];
}

document.addEventListener('DOMContentLoaded', () => {
    const chatButton = document.getElementById('chatButton');
    const chatSend = document.getElementById('chatSend');
    const chatbotBtn = document.getElementById('chatbotBtn');
    const chatbotSend = document.getElementById('chatbotSend');
    const chatbotInput = document.getElementById('chatbotInput');

    if (chatButton) {
        chatButton.addEventListener('click', toggleChat);
    }

    if (chatSend) {
        chatSend.addEventListener('click', sendMessage);
    }

    // Homepage chatbot event listeners
    if (chatbotBtn) {
        chatbotBtn.addEventListener('click', toggleChatbot);
    }

    if (chatbotSend) {
        chatbotSend.addEventListener('click', sendChatbotMessage);
    }

    if (chatbotInput) {
        chatbotInput.addEventListener('keypress', handleChatbotKeyPress);
    }
});

// Wishlist functionality
async function addToWishlist(productId) {
  if (!isLoggedIn()) {
    // For guest users, use localStorage
    let wishlist = JSON.parse(localStorage.getItem('guestWishlist') || '[]');
    if (!wishlist.includes(productId)) {
      wishlist.push(productId);
      localStorage.setItem('guestWishlist', JSON.stringify(wishlist));
      showToast('Added to wishlist!', 'success');
      updateWishlistButton(productId, true);
    } else {
      showToast('Already in wishlist', 'info');
    }
    return;
  }

  try {
    const response = await apiCall('/wishlist/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product_id: productId })
    });

    if (response.success) {
      showToast('Added to wishlist!', 'success');
      updateWishlistButton(productId, true);
    }
  } catch (error) {
    console.error('Error adding to wishlist:', error);
    showToast('Failed to add to wishlist', 'error');
  }
}

async function removeFromWishlist(productId) {
  if (!isLoggedIn()) {
    // For guest users, use localStorage
    let wishlist = JSON.parse(localStorage.getItem('guestWishlist') || '[]');
    const index = wishlist.indexOf(productId);
    if (index > -1) {
      wishlist.splice(index, 1);
      localStorage.setItem('guestWishlist', JSON.stringify(wishlist));
      showToast('Removed from wishlist!', 'success');
      updateWishlistButton(productId, false);
    }
    return;
  }

  try {
    const response = await apiCall('/wishlist/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product_id: productId })
    });

    if (response.success) {
      showToast('Removed from wishlist!', 'success');
      updateWishlistButton(productId, false);
    }
  } catch (error) {
    console.error('Error removing from wishlist:', error);
    showToast('Failed to remove from wishlist', 'error');
  }
}

function updateWishlistButton(productId, isInWishlist) {
  const buttons = document.querySelectorAll(`[data-product-id="${productId}"] .wishlist-btn`);
  buttons.forEach(btn => {
    if (isInWishlist) {
      btn.classList.add('active');
      btn.innerHTML = '<i class="fas fa-heart"></i>';
    } else {
      btn.classList.remove('active');
      btn.innerHTML = '<i class="far fa-heart"></i>';
    }
  });
}

async function checkWishlistStatus(productId) {
  if (!isLoggedIn()) {
    const wishlist = JSON.parse(localStorage.getItem('guestWishlist') || '[]');
    return wishlist.includes(productId);
  }

  try {
    const response = await apiCall('/wishlist');
    const wishlist = response.wishlist || [];
    return wishlist.some(product => product._id === productId);
  } catch (error) {
    console.error('Error checking wishlist status:', error);
    return false;
  }
}

async function toggleWishlist(productId) {
  const isInWishlist = await checkWishlistStatus(productId);
  if (isInWishlist) {
    await removeFromWishlist(productId);
  } else {
    await addToWishlist(productId);
  }
}

async function loadWishlistPage() {
  const wishlistGrid = document.getElementById('wishlist-grid');
  if (!wishlistGrid) return;

  wishlistGrid.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i> Loading wishlist...</div>';

  try {
    let products = [];

    if (isLoggedIn()) {
      const response = await apiCall('/wishlist');
      products = response.wishlist || [];
    } else {
      // For guest users, get from localStorage and fetch product details
      const wishlistIds = JSON.parse(localStorage.getItem('guestWishlist') || '[]');
      if (wishlistIds.length > 0) {
        const response = await apiCall('/products');
        const allProducts = response.products || [];
        products = allProducts.filter(product => wishlistIds.includes(product._id));
      }
    }

    wishlistGrid.innerHTML = '';

    if (products.length === 0) {
      wishlistGrid.innerHTML = `
        <div class="empty-wishlist">
          <i class="fas fa-heart-broken"></i>
          <h3>Your wishlist is empty</h3>
          <p>Start browsing and add items you love!</p>
          <a href="products.html" class="btn btn-primary">Browse Products</a>
        </div>
      `;
      return;
    }

    products.forEach(product => {
      const card = document.createElement('div');
      card.className = 'wishlist-item';
      card.setAttribute('data-product-id', product._id);

      const imageUrl = product.images?.[0]
        ? (product.images[0].startsWith('http') ? product.images[0] : IMAGE_BASE_URL + '/' + product.images[0].replace(/^\/+/, ''))
        : "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=300&fit=crop";

      card.innerHTML = `
        <div class="wishlist-item-image">
          <a href="product.html?id=${product._id}">
            <img src="${imageUrl}" alt="${product.title}">
          </a>
          <button class="remove-wishlist-btn" onclick="removeFromWishlist('${product._id}')">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="wishlist-item-info">
          <h3><a href="product.html?id=${product._id}">${product.title}</a></h3>
          <div class="wishlist-item-price">₹${product.price} /${product.rental_type}</div>
          <div class="wishlist-item-location">
            <i class="fas fa-map-marker-alt"></i> ${product.location || 'Location not specified'}
          </div>
          <button class="btn btn-primary" onclick="window.location.href='product.html?id=${product._id}'">
            View Details
          </button>
        </div>
      `;

      wishlistGrid.appendChild(card);
    });

  } catch (error) {
    console.error('Error loading wishlist:', error);
    wishlistGrid.innerHTML = `
      <div class="error-message">
        <i class="fas fa-exclamation-triangle"></i>
        <h3>Failed to load wishlist</h3>
        <p>Please try again later.</p>
      </div>
    `;
  }
}

// Toast notification function
function showToast(message, type) {
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    toastMessage.textContent = message;
    toast.classList.add('show', type);
    setTimeout(() => {
        toast.classList.remove('show', type);
    }, 3000);
}


// Navigation functions for product.html
function navigateHome() {
    window.location.href = 'index.html';
}

function navigateProducts(event) {
    event.preventDefault();
    window.location.href = 'products.html';
}

function navigateCategories(event) {
    event.preventDefault();
    window.location.href = 'index.html#categories'; // Assuming categories section is on index.html
}

function navigateAbout(event) {
    event.preventDefault();
    window.location.href = 'index.html#about'; // Assuming about section is on index.html
}

// Function to update cart count across all pages
async function updateCartCount() {
    try {
        let count = 0;

        if (isLoggedIn()) {
            const response = await apiCall('/cart');
            const cart = response.cart || [];
            count = cart.reduce((total, item) => total + (item.cart_quantity || 1), 0);
        } else {
            const cart = JSON.parse(localStorage.getItem('guestCart') || '[]');
            count = cart.reduce((total, item) => total + (item.quantity || 1), 0);
        }

        const cartCountEl = document.getElementById('cartCount');
        if (cartCountEl) {
            cartCountEl.textContent = count;
        }
    } catch (error) {
        console.error('Error updating cart count:', error);
    }
}

function toggleCart() {
    // Navigate to cart page
    window.location.href = 'cart.html';
}

// Event listeners for window loading
window.addEventListener('load', () => {
    showLoadingSpinner();
    fetchProductData();
});

// Homepage chatbot functions
function toggleChatbot() {
    const chatbotWindow = document.getElementById('chatbotWindow');
    const chatbotMessages = document.getElementById('chatbotMessages');

    if (chatbotWindow.style.display === 'flex') {
        chatbotWindow.style.display = 'none';
    } else {
        chatbotWindow.style.display = 'flex';

        // Load existing messages if empty
        if (chatbotMessages && chatbotMessages.children.length === 0) {
            loadChatbotMessages();
        }

        document.getElementById('chatbotInput').focus();
    }
}

function closeChatbot() {
    document.getElementById('chatbotWindow').style.display = 'none';
}

function clearChatbot() {
    const chatbotMessages = document.getElementById('chatbotMessages');
    if (chatbotMessages) {
        chatbotMessages.innerHTML = '';
    }
}

async function sendChatbotMessage() {
    const chatbotInput = document.getElementById('chatbotInput');
    const chatbotMessages = document.getElementById('chatbotMessages');
    const message = chatbotInput.value.trim();
    if (message === '') return;

    // Append user message immediately
    const userMessageElement = document.createElement('div');
    userMessageElement.classList.add('chatbot-message', 'sent');
    userMessageElement.innerHTML = `<strong>You:</strong> ${message}`;
    chatbotMessages.appendChild(userMessageElement);

    chatbotInput.value = '';
    chatbotMessages.scrollTop = chatbotMessages.scrollHeight;

    // Get bot response
    const botResponse = getBotResponse(message);

    // Append bot response
    const botMessageElement = document.createElement('div');
    botMessageElement.classList.add('chatbot-message', 'received');
    botMessageElement.innerHTML = `<strong>RentHuB Assistant:</strong> ${botResponse}`;
    chatbotMessages.appendChild(botMessageElement);

    chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
}

function handleChatbotKeyPress(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendChatbotMessage();
    }
}

function loadChatbotMessages() {
    // For now, just show a welcome message
    const chatbotMessages = document.getElementById('chatbotMessages');
    if (!chatbotMessages) return;

    const welcomeMessage = document.createElement('div');
    welcomeMessage.classList.add('chatbot-message', 'received');
    welcomeMessage.innerHTML = `<strong>RentHuB Assistant:</strong> Hi! 👋 Welcome to RentHuB! How can I help you today?`;
    chatbotMessages.appendChild(welcomeMessage);
}






