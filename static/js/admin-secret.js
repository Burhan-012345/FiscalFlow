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
      this.redirectToAdmin();
    }

    // Alt + A shortcut
    if (e.altKey && e.key === "a") {
      this.redirectToAdmin();
    }

    // Ctrl + Shift + A shortcut
    if (e.ctrlKey && e.shiftKey && e.key === "A") {
      this.redirectToAdmin();
    }
  }

  handleTouch(e) {
    const currentTime = new Date().getTime();
    const tapLength = currentTime - this.lastTapTime;

    if (tapLength < 500 && tapLength > 0) {
      this.tapCount++;
      if (this.tapCount === 3) {
        this.redirectToAdmin();
        this.tapCount = 0;
      }
    } else {
      this.tapCount = 1;
    }

    this.lastTapTime = currentTime;
  }

  setupLongPress() {
    const userAvatar = document.querySelector(
      ".navbar-brand img, .user-avatar, .avatar"
    );
    if (userAvatar) {
      let pressTimer;

      userAvatar.addEventListener("touchstart", (e) => {
        pressTimer = setTimeout(() => {
          this.redirectToAdmin();
        }, 3000); // 3 second long press
      });

      userAvatar.addEventListener("touchend", () => {
        clearTimeout(pressTimer);
      });

      userAvatar.addEventListener("mousedown", (e) => {
        pressTimer = setTimeout(() => {
          this.redirectToAdmin();
        }, 3000);
      });

      userAvatar.addEventListener("mouseup", () => {
        clearTimeout(pressTimer);
      });

      userAvatar.addEventListener("mouseleave", () => {
        clearTimeout(pressTimer);
      });
    }
  }

  redirectToAdmin() {
    // Check if user is logged in and has admin rights
    fetch("/api/check-admin-access")
      .then((response) => response.json())
      .then((data) => {
        if (data.has_access) {
          window.location.href = "/secret-admin";
        } else {
          this.showAccessDenied();
        }
      })
      .catch(() => {
        this.showAccessDenied();
      });
  }

  showAccessDenied() {
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
      document.body.removeChild(deniedMsg);
    }, 2000);
  }
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new AdminSecret();
});
