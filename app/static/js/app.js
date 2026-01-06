// Custom JavaScript for HomeLab PKI

// ============================================
// Toast Notification System
// ============================================

/**
 * Show a toast notification
 * @param {string} message - The message to display
 * @param {string} type - 'success', 'error', 'warning', 'info'
 * @param {number} duration - Auto-hide duration in ms (0 = no auto-hide)
 */
function showToast(message, type = 'info', duration = 5000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toastId = 'toast-' + Date.now();
    const iconMap = {
        success: 'bi-check-circle-fill',
        error: 'bi-exclamation-triangle-fill',
        warning: 'bi-exclamation-circle-fill',
        info: 'bi-info-circle-fill'
    };
    const bgMap = {
        success: 'text-bg-success',
        error: 'text-bg-danger',
        warning: 'text-bg-warning',
        info: 'text-bg-primary'
    };

    const icon = iconMap[type] || iconMap.info;
    const bg = bgMap[type] || bgMap.info;

    const toastHtml = `
        <div id="${toastId}" class="toast align-items-center ${bg} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="bi ${icon} me-2"></i>
                    ${escapeHtml(message)}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;

    container.insertAdjacentHTML('beforeend', toastHtml);
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, {
        autohide: duration > 0,
        delay: duration
    });

    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });

    toast.show();
}

/**
 * Show a success toast
 */
function showSuccess(message, duration = 3000) {
    showToast(message, 'success', duration);
}

/**
 * Show an error toast
 */
function showError(message, duration = 8000) {
    showToast(message, 'error', duration);
}

/**
 * Show a warning toast
 */
function showWarning(message, duration = 5000) {
    showToast(message, 'warning', duration);
}

/**
 * Show an info toast
 */
function showInfo(message, duration = 5000) {
    showToast(message, 'info', duration);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// Confirmation Modal System
// ============================================

/**
 * Show a confirmation modal and return a promise
 * @param {string} message - The message to display
 * @param {Object} options - Configuration options
 * @param {string} options.title - Modal title (default: 'Confirm')
 * @param {string} options.confirmText - Confirm button text (default: 'Confirm')
 * @param {string} options.cancelText - Cancel button text (default: 'Cancel')
 * @param {string} options.confirmClass - Confirm button class (default: 'btn-danger')
 * @returns {Promise<boolean>} - Resolves to true if confirmed, false if cancelled
 */
function showConfirm(message, options = {}) {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirmModal');
        if (!modal) {
            resolve(window.confirm(message)); // Fallback to native confirm
            return;
        }

        const title = options.title || 'Confirm';
        const confirmText = options.confirmText || 'Confirm';
        const cancelText = options.cancelText || 'Cancel';
        const confirmClass = options.confirmClass || 'btn-danger';

        document.getElementById('confirmModalLabel').textContent = title;
        document.getElementById('confirmModalBody').innerHTML = escapeHtml(message).replace(/\n/g, '<br>');

        const okBtn = document.getElementById('confirmModalOk');
        const cancelBtn = document.getElementById('confirmModalCancel');

        okBtn.textContent = confirmText;
        okBtn.className = 'btn ' + confirmClass;
        cancelBtn.textContent = cancelText;

        const bsModal = new bootstrap.Modal(modal);

        const cleanup = () => {
            okBtn.removeEventListener('click', onConfirm);
            modal.removeEventListener('hidden.bs.modal', onCancel);
        };

        const onConfirm = () => {
            cleanup();
            bsModal.hide();
            resolve(true);
        };

        const onCancel = () => {
            cleanup();
            resolve(false);
        };

        okBtn.addEventListener('click', onConfirm);
        modal.addEventListener('hidden.bs.modal', onCancel);

        bsModal.show();
    });
}

// ============================================
// Bootstrap form validation
// ============================================

// Bootstrap form validation
(function () {
    'use strict';

    // Fetch all forms that need validation
    var forms = document.querySelectorAll('.needs-validation');

    // Loop over them and prevent submission
    Array.prototype.slice.call(forms).forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
})();

// Dark Mode Toggle
document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = themeToggle.querySelector('i');
    const htmlElement = document.documentElement;

    // Check for saved theme preference or system preference
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'dark' || (!savedTheme && systemPrefersDark)) {
        setTheme('dark');
    } else {
        setTheme('light');
    }

    themeToggle.addEventListener('click', () => {
        const currentTheme = htmlElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    });

    function setTheme(theme) {
        htmlElement.setAttribute('data-bs-theme', theme);
        localStorage.setItem('theme', theme);

        if (theme === 'dark') {
            themeIcon.classList.remove('bi-moon-fill');
            themeIcon.classList.add('bi-sun-fill');
            themeToggle.classList.remove('btn-outline-light');
            themeToggle.classList.add('btn-outline-warning');
        } else {
            themeIcon.classList.remove('bi-sun-fill');
            themeIcon.classList.add('bi-moon-fill');
            themeToggle.classList.remove('btn-outline-warning');
            themeToggle.classList.add('btn-outline-light');
        }
    }
});
