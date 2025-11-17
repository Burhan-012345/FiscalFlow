// Secret admin access keyboard shortcuts
class AdminSecret {
  constructor() {
    this.keySequence = [];
    this.secretCode = "38384040373937396665"; // Konami code: ↑↑↓↓←→←→BA
    this.tapCount = 0;
    this.lastTapTime = 0;
    this.init();
  }

  init() {
    console.log("AdminSecret initialized");

    // Keyboard shortcut
    document.addEventListener("keydown", (e) => {
      this.handleKeyPress(e);
    });

    // Double-tap for mobile
    document.addEventListener("touchstart", (e) => {
      this.handleTouch(e);
    });

    // Long press on user avatar/logo
    this.setupLongPress();
  }

  handleKeyPress(e) {
    this.keySequence.push(e.keyCode);

    // Keep only last 10 keys
    if (this.keySequence.length > 10) {
      this.keySequence.shift();
    }

    // Check for Konami code
    if (this.keySequence.join("") === this.secretCode) {
      console.log("Konami code detected!");
      this.redirectToAdmin();
    }

    // Alt + A shortcut
    if (e.altKey && e.key === "a") {
      console.log("Alt+A detected!");
      this.redirectToAdmin();
    }

    // Ctrl + Shift + A shortcut
    if (e.ctrlKey && e.shiftKey && e.key === "A") {
      console.log("Ctrl+Shift+A detected!");
      this.redirectToAdmin();
    }
  }

  handleTouch(e) {
    const currentTime = new Date().getTime();
    const tapLength = currentTime - this.lastTapTime;

    if (tapLength < 500 && tapLength > 0) {
      this.tapCount++;
      if (this.tapCount === 3) {
        console.log("Triple tap detected!");
        this.redirectToAdmin();
        this.tapCount = 0;
      }
    } else {
      this.tapCount = 1;
    }

    this.lastTapTime = currentTime;
  }

  setupLongPress() {
    // Try multiple selectors for the avatar/logo
    const userAvatar =
      document.querySelector("#navbarLogo") ||
      document.querySelector(".navbar-brand img") ||
      document.querySelector(".user-avatar") ||
      document.querySelector(".avatar") ||
      document.querySelector(".nav-link.dropdown-toggle i.fa-user-circle")
        .parentElement;

    if (userAvatar) {
      console.log("Avatar element found for long press");
      let pressTimer;

      userAvatar.addEventListener("touchstart", (e) => {
        pressTimer = setTimeout(() => {
          console.log("Long press detected!");
          this.redirectToAdmin();
        }, 3000); // 3 second long press
      });

      userAvatar.addEventListener("touchend", () => {
        clearTimeout(pressTimer);
      });

      userAvatar.addEventListener("mousedown", (e) => {
        pressTimer = setTimeout(() => {
          console.log("Long press detected!");
          this.redirectToAdmin();
        }, 3000);
      });

      userAvatar.addEventListener("mouseup", () => {
        clearTimeout(pressTimer);
      });

      userAvatar.addEventListener("mouseleave", () => {
        clearTimeout(pressTimer);
      });
    } else {
      console.log("No avatar element found for long press");
    }
  }

  redirectToAdmin() {
    console.log("Attempting to access admin...");

    // Check if user is logged in and has admin rights
    fetch("/api/check-admin-access")
      .then((response) => response.json())
      .then((data) => {
        console.log("Admin access check:", data);
        if (data.has_access) {
          // Use the correct Flask route
          window.location.href = "/admin-access";
        } else {
          this.showAccessDenied();
        }
      })
      .catch((error) => {
        console.error("Admin access check failed:", error);
        this.showAccessDenied();
      });
  }

  showAccessDenied() {
    console.log("Showing access denied message");

    // Create a subtle access denied message
    const deniedMsg = document.createElement("div");
    deniedMsg.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #dc3545;
      color: white;
      padding: 10px 15px;
      border-radius: 5px;
      z-index: 9999;
      font-size: 14px;
    `;
    deniedMsg.textContent = "Access Denied";
    document.body.appendChild(deniedMsg);

    setTimeout(() => {
      if (document.body.contains(deniedMsg)) {
        document.body.removeChild(deniedMsg);
      }
    }, 2000);
  }
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM loaded, initializing AdminSecret...");
  new AdminSecret();
});
