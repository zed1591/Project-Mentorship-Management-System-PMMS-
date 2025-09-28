// Background selector functionality
document.addEventListener('DOMContentLoaded', function() {
    // Background selector toggle
    const bgToggle = document.getElementById('bg-toggle');
    const bgOptions = document.getElementById('bg-options');
    
    if (bgToggle && bgOptions) {
        bgToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            bgOptions.classList.toggle('active');
        });
        
        // Close background options when clicking outside
        document.addEventListener('click', function(e) {
            if (bgOptions.classList.contains('active') && 
                !bgOptions.contains(e.target) && 
                !bgToggle.contains(e.target)) {
                bgOptions.classList.remove('active');
            }
        });
        
        // Prevent options from closing when clicking on them
        bgOptions.addEventListener('click', function(e) {
            e.stopPropagation();
        });
        
        // Background selection
        const bgOptionsElements = document.querySelectorAll('.bg-option');
        bgOptionsElements.forEach(option => {
            option.addEventListener('click', function() {
                const bgType = this.getAttribute('data-bg');
                changeBackground(bgType);
                bgOptions.classList.remove('active');
            });
        });
    }
    
    // Theme toggle functionality
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            document.body.classList.toggle('night-mode');
            const icon = this.querySelector('i');
            if (document.body.classList.contains('night-mode')) {
                icon.classList.remove('fa-moon');
                icon.classList.add('fa-sun');
            } else {
                icon.classList.remove('fa-sun');
                icon.classList.add('fa-moon');
            }
        });
    }
    
    // Video fallback handling
    const video = document.getElementById('background-video');
    if (video) {
        // Check if video has valid sources
        const hasValidSources = Array.from(video.querySelectorAll('source')).some(source => {
            return source.src && !source.src.includes('undefined');
        });
        
        // If no valid sources, hide video and use gradient fallback
        if (!hasValidSources) {
            video.style.display = 'none';
            const videoBackground = document.querySelector('.video-background');
            if (videoBackground) {
                videoBackground.classList.add('video-fallback');
            }
        }
        
        // Handle video loading errors
        video.addEventListener('error', function() {
            this.style.display = 'none';
            const videoBackground = document.querySelector('.video-background');
            if (videoBackground) {
                videoBackground.classList.add('video-fallback');
            }
        });
    }
});

// Background changing function
function changeBackground(bgType) {
    // Remove all background classes
    document.body.classList.remove('body-gradient1', 'body-gradient2', 'body-solid');
    
    // Hide video background by default
    const videoBackground = document.querySelector('.video-background');
    if (videoBackground) {
        videoBackground.style.display = 'block';
    }
    
    // Apply selected background
    if (bgType !== 'video') {
        document.body.classList.add('body-' + bgType);
        if (videoBackground) {
            videoBackground.style.display = 'none';
        }
    }
    
    // Save preference to localStorage
    localStorage.setItem('backgroundPreference', bgType);
}

// Notification system
function showNotification(title, message, type = 'info') {
    const notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) return;
    
    const icons = {
        info: 'fas fa-info-circle',
        success: 'fas fa-check-circle',
        warning: 'fas fa-exclamation-triangle',
        error: 'fas fa-exclamation-circle'
    };
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="${icons[type]}"></i>
        <div class="notification-content">
            <div class="notification-title">${title}</div>
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close"><i class="fas fa-times"></i></button>
    `;
    
    notificationContainer.appendChild(notification);
    
    // Add close functionality
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        notification.style.animation = 'fadeOut 0.5s ease forwards';
        setTimeout(() => {
            notification.remove();
        }, 500);
    });
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'fadeOut 0.5s ease forwards';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 500);
        }
    }, 5000);
}

// Load saved background preference
document.addEventListener('DOMContentLoaded', function() {
    const savedBg = localStorage.getItem('backgroundPreference');
    if (savedBg) {
        changeBackground(savedBg);
    }
});
