// Main JavaScript for FiscalFlow
document.addEventListener("DOMContentLoaded", function () {
  // Initialize dark mode
  initDarkMode();

  // Initialize startup modal
  initStartupModal();

  // Initialize tooltips
  initTooltips();

  // Initialize password strength meter
  initPasswordStrength();

  // Initialize form validations
  initFormValidations();
});

// Dark Mode Functionality
function initDarkMode() {
  const darkModeToggle = document.getElementById("darkModeToggle");
  const darkModeStylesheet = document.getElementById("darkModeStylesheet");

  // Check for saved theme preference or respect OS preference
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const savedTheme = localStorage.getItem("theme");

  if (savedTheme === "dark" || (!savedTheme && prefersDark)) {
    enableDarkMode();
  }

  if (darkModeToggle) {
    darkModeToggle.addEventListener("click", function () {
      if (document.body.classList.contains("dark-mode")) {
        disableDarkMode();
      } else {
        enableDarkMode();
      }
    });
  }
}

function enableDarkMode() {
  document.body.classList.add("dark-mode");
  localStorage.setItem("theme", "dark");
  updateDarkModeIcon(true);
}

function disableDarkMode() {
  document.body.classList.remove("dark-mode");
  localStorage.setItem("theme", "light");
  updateDarkModeIcon(false);
}

function updateDarkModeIcon(isDark) {
  const icon = document.querySelector("#darkModeToggle i");
  if (icon) {
    icon.className = isDark ? "fas fa-sun" : "fas fa-moon";
  }
}

// Startup Modal
function initStartupModal() {
  const startupModal = new bootstrap.Modal(
    document.getElementById("startupModal")
  );

  // Show modal only on first visit
  if (!localStorage.getItem("startupModalShown")) {
    setTimeout(() => {
      startupModal.show();
      localStorage.setItem("startupModalShown", "true");
    }, 1000);
  }
}

// Tooltips
function initTooltips() {
  const tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });
}

// Password Strength Meter
function initPasswordStrength() {
  const passwordInput = document.getElementById("password");
  const strengthBar = document.getElementById("password-strength-bar");
  const strengthText = document.getElementById("password-strength-text");

  if (passwordInput && strengthBar && strengthText) {
    passwordInput.addEventListener("input", function () {
      const password = this.value;
      const strength = calculatePasswordStrength(password);

      updateStrengthMeter(strength, strengthBar, strengthText);
    });
  }
}

function calculatePasswordStrength(password) {
  let strength = 0;

  if (password.length >= 8) strength += 1;
  if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength += 1;
  if (password.match(/\d/)) strength += 1;
  if (password.match(/[^a-zA-Z\d]/)) strength += 1;

  return strength;
}

function updateStrengthMeter(strength, bar, text) {
  const strengthLabels = ["Very Weak", "Weak", "Fair", "Good", "Strong"];
  const strengthClasses = ["danger", "danger", "warning", "info", "success"];
  const strengthWidths = ["20%", "40%", "60%", "80%", "100%"];

  bar.className = `strength-bar strength-${strengthClasses[strength]}`;
  bar.style.width = strengthWidths[strength];
  text.textContent = strengthLabels[strength];
  text.className = `text-${strengthClasses[strength]}`;
}

// Form Validations
function initFormValidations() {
  // Real-time email validation
  const emailInputs = document.querySelectorAll('input[type="email"]');
  emailInputs.forEach((input) => {
    input.addEventListener("blur", function () {
      validateEmail(this);
    });
  });

  // Password confirmation validation
  const passwordConfirmInputs = document.querySelectorAll(
    'input[name="confirm_password"]'
  );
  passwordConfirmInputs.forEach((input) => {
    input.addEventListener("input", function () {
      validatePasswordConfirmation(this);
    });
  });
}

function validateEmail(input) {
  const email = input.value;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (email && !emailRegex.test(email)) {
    showValidationError(input, "Please enter a valid email address");
    return false;
  } else {
    clearValidationError(input);
    return true;
  }
}

function validatePasswordConfirmation(input) {
  const passwordInput = document.getElementById("password");
  const confirmPassword = input.value;

  if (
    passwordInput &&
    confirmPassword &&
    passwordInput.value !== confirmPassword
  ) {
    showValidationError(input, "Passwords do not match");
    return false;
  } else {
    clearValidationError(input);
    return true;
  }
}

function showValidationError(input, message) {
  clearValidationError(input);

  input.classList.add("is-invalid");

  const errorDiv = document.createElement("div");
  errorDiv.className = "invalid-feedback";
  errorDiv.textContent = message;

  input.parentNode.appendChild(errorDiv);
}

function clearValidationError(input) {
  input.classList.remove("is-invalid");

  const existingError = input.parentNode.querySelector(".invalid-feedback");
  if (existingError) {
    existingError.remove();
  }
}

// Loading Screen Management
function showLoadingScreen(redirectUrl = null) {
  const loadingScreen = document.getElementById("loadingScreen");
  if (loadingScreen) {
    loadingScreen.style.display = "flex";

    if (redirectUrl) {
      setTimeout(() => {
        window.location.href = redirectUrl;
      }, 3000);
    }
  }
}

// API Calls
async function makeAPICall(url, method = "GET", data = null) {
  const options = {
    method: method,
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
  };

  if (data && (method === "POST" || method === "PUT")) {
    options.body = JSON.stringify(data);
  }

  try {
    const response = await fetch(url, options);
    return await response.json();
  } catch (error) {
    console.error("API call failed:", error);
    throw error;
  }
}

// Notification System
function showNotification(message, type = "info", duration = 5000) {
  // Create notification element
  const notification = document.createElement("div");
  notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
  notification.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    `;

  notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

  // Add to page
  document.body.appendChild(notification);

  // Auto remove after duration
  if (duration > 0) {
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, duration);
  }
}

// Export functions for global use
window.FiscalFlow = {
  showLoadingScreen,
  showNotification,
  makeAPICall,
  enableDarkMode,
  disableDarkMode,
};
