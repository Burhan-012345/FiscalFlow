// Additional validation functions
document.addEventListener("DOMContentLoaded", function () {
  // OTP input validation
  const otpInputs = document.querySelectorAll(".otp-input");
  otpInputs.forEach((input, index) => {
    input.addEventListener("input", function () {
      if (this.value.length === 1 && index < otpInputs.length - 1) {
        otpInputs[index + 1].focus();
      }
    });

    input.addEventListener("keydown", function (e) {
      if (e.key === "Backspace" && this.value.length === 0 && index > 0) {
        otpInputs[index - 1].focus();
      }
    });
  });

  // Amount validation
  const amountInputs = document.querySelectorAll('input[type="number"]');
  amountInputs.forEach((input) => {
    input.addEventListener("blur", function () {
      const value = parseFloat(this.value);
      if (value < 0) {
        showValidationError(this, "Amount cannot be negative");
      } else {
        clearValidationError(this);
      }
    });
  });

  // Credit limit validation
  const creditLimitInputs = document.querySelectorAll(
    'input[name="credit_limit"]'
  );
  creditLimitInputs.forEach((input) => {
    input.addEventListener("blur", function () {
      const value = parseFloat(this.value);
      if (value < 0) {
        showValidationError(this, "Credit limit cannot be negative");
      } else {
        clearValidationError(this);
      }
    });
  });
});

// Form submission validation
function validateForm(formId) {
  const form = document.getElementById(formId);
  if (!form) return true;

  const inputs = form.querySelectorAll("input, select, textarea");
  let isValid = true;

  inputs.forEach((input) => {
    if (input.hasAttribute("required") && !input.value.trim()) {
      showValidationError(input, "This field is required");
      isValid = false;
    }

    if (input.type === "email" && input.value) {
      if (!validateEmail(input)) {
        isValid = false;
      }
    }
  });

  return isValid;
}

// File upload validation
function validateFileUpload(input, maxSizeMB = 16) {
  if (!input.files || !input.files[0]) return true;

  const file = input.files[0];
  const maxSize = maxSizeMB * 1024 * 1024;

  if (file.size > maxSize) {
    showValidationError(input, `File size must be less than ${maxSizeMB}MB`);
    return false;
  }

  const allowedTypes = [
    "image/jpeg",
    "image/png",
    "image/jpg",
    "application/pdf",
  ];
  if (!allowedTypes.includes(file.type)) {
    showValidationError(input, "Please upload a PDF, JPG, or PNG file");
    return false;
  }

  clearValidationError(input);
  return true;
}

// Transaction form validation
function validateTransactionForm() {
  const amountInput = document.querySelector('input[name="amount"]');
  const dateInput = document.querySelector('input[name="date"]');
  const typeInput = document.querySelector('select[name="type"]');

  let isValid = true;

  if (
    amountInput &&
    (!amountInput.value || parseFloat(amountInput.value) <= 0)
  ) {
    showValidationError(amountInput, "Please enter a valid amount");
    isValid = false;
  }

  if (dateInput && !dateInput.value) {
    showValidationError(dateInput, "Please select a date");
    isValid = false;
  }

  if (typeInput && !typeInput.value) {
    showValidationError(typeInput, "Please select a transaction type");
    isValid = false;
  }

  return isValid;
}

// Customer form validation
function validateCustomerForm() {
  const nameInput = document.querySelector('input[name="name"]');
  const emailInput = document.querySelector('input[name="email"]');

  let isValid = true;

  if (nameInput && !nameInput.value.trim()) {
    showValidationError(nameInput, "Customer name is required");
    isValid = false;
  }

  if (emailInput && emailInput.value && !validateEmail(emailInput)) {
    isValid = false;
  }

  return isValid;
}
