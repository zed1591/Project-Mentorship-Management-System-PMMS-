document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard
    initDashboard();
});

// Configuration
const CONFIG = {
    NOTIFICATION_DURATION: 5000,
    AUTO_REFRESH_DELAY: 1000,
    API_ENDPOINTS: {
        ANALYTICS: '/api/summary_analytics',
        MENTORS: '/api/available_mentors',
        MENTOR_MATCH: '/api/mentor_match'
    }
};

// State management
const DashboardState = {
    isLoading: false,
    currentProject: null,
    mentors: [],
    csrfToken: null
};

async function initDashboard() {
    try {
        DashboardState.isLoading = true;
        showLoadingState(true);
        
        // Get CSRF token first
        await getCSRFToken();
        
        // Load all initial data in parallel
        await Promise.all([
            loadAnalytics(),
            loadMentors()
        ]);
        
        // Set up event listeners
        setupEventListeners();
        
        // Initialize charts if needed
        initCharts();
        
    } catch (error) {
        console.error('Dashboard initialization error:', error);
        showNotification('Failed to load dashboard data. Please refresh the page.', 'error');
    } finally {
        DashboardState.isLoading = false;
        showLoadingState(false);
    }
}

function getCSRFToken() {
    return new Promise((resolve, reject) => {
        try {
            // Flask-WTF CSRF token is typically in a meta tag or form field
            // Check for meta tag first
            const metaToken = document.querySelector('meta[name="csrf-token"]');
            if (metaToken) {
                DashboardState.csrfToken = metaToken.getAttribute('content');
                console.log('CSRF token found in meta tag');
                resolve();
                return;
            }
            
            // Check for hidden input field in forms (common Flask-WTF pattern)
            const formToken = document.querySelector('input[name="csrf_token"]');
            if (formToken) {
                DashboardState.csrfToken = formToken.value;
                console.log('CSRF token found in form field');
                resolve();
                return;
            }
            
            // Try to get from cookie as fallback
            const cookieToken = getCookie('csrf_token') || getCookie('XSRF-TOKEN');
            if (cookieToken) {
                DashboardState.csrfToken = cookieToken;
                console.log('CSRF token found in cookie');
                resolve();
                return;
            }
            
            console.warn('No CSRF token found. Some POST requests may fail.');
            resolve(); // Continue without token
            
        } catch (error) {
            console.warn('Error getting CSRF token:', error);
            resolve(); // Don't block initialization
        }
    });
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}
// Add this to the getCSRFToken() function after the cookie check:
if (!DashboardState.csrfToken) {
    try {
        const response = await fetch('/api/csrf-token');
        if (response.ok) {
            const data = await response.json();
            DashboardState.csrfToken = data.csrf_token;
            console.log('CSRF token fetched from API');
        }
    } catch (error) {
        console.warn('Failed to fetch CSRF token from API:', error);
    }
}
async function loadAnalytics() {
    try {
        const data = await apiCall(CONFIG.API_ENDPOINTS.ANALYTICS);
        
        // Update statistics cards
        updateStatCard('mentor-count', data.users_by_role?.Mentor || 0);
        updateStatCard('mentee-count', data.users_by_role?.Mentee || 0);
        updateStatCard('project-count', data.total_projects || 0);
        updateStatCard('completion-rate', data.completion_rate ? `${data.completion_rate}%` : '0%');
        
        // Update additional analytics if available
        if (data.recent_activity) {
            updateRecentActivity(data.recent_activity);
        }
        
    } catch (error) {
        console.error('Error loading analytics:', error);
        showNotification('Failed to load statistics', 'error');
    }
}

function updateStatCard(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
        
        // Add animation effect
        element.classList.add('stat-update');
        setTimeout(() => element.classList.remove('stat-update'), 300);
    }
}

function updateRecentActivity(activities) {
    const container = document.getElementById('recent-activity');
    if (!container) return;
    
    container.innerHTML = activities.map(activity => `
        <div class="activity-item">
            <span class="activity-time">${new Date(activity.timestamp).toLocaleTimeString()}</span>
            <span class="activity-text">${activity.description}</span>
        </div>
    `).join('');
}

async function loadMentors() {
    try {
        const mentors = await apiCall(CONFIG.API_ENDPOINTS.MENTORS);
        DashboardState.mentors = mentors;
        
        const select = document.getElementById('mentorSelect');
        if (!select) return;
        
        select.innerHTML = '<option value="">Choose a mentor...</option>';
        mentors.forEach(mentor => {
            const option = document.createElement('option');
            option.value = mentor._id;
            option.textContent = mentor.profile?.full_name || mentor.username;
            option.title = mentor.profile?.expertise ? `Expertise: ${mentor.profile.expertise.join(', ')}` : '';
            select.appendChild(option);
        });
        
    } catch (error) {
        console.error('Error loading mentors:', error);
        showNotification('Failed to load mentors list', 'warning');
    }
}

function setupEventListeners() {
    // Assign mentor form submission
    const assignForm = document.getElementById('assignMentorForm');
    if (assignForm) {
        assignForm.addEventListener('submit', handleAssignMentor);
    }
    
    // Modal events
    const modal = document.getElementById('assignMentorModal');
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal();
            }
        });
    }
    
    // Escape key to close modal
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && modal && !modal.classList.contains('hidden')) {
            closeModal();
        }
    });
    
    // Refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', handleRefresh);
    }
    
    // Export button
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportData);
    }
}

function openAssignMentorModal(projectId, projectTitle, menteeName) {
    const modal = document.getElementById('assignMentorModal');
    const projectIdInput = document.getElementById('projectId');
    const titleElement = document.getElementById('projectTitle');
    const menteeElement = document.getElementById('menteeName');
    
    if (!modal || !projectIdInput || !titleElement || !menteeElement) {
        console.error('Modal elements not found');
        showNotification('Modal configuration error', 'error');
        return;
    }
    
    DashboardState.currentProject = { projectId, projectTitle, menteeName };
    projectIdInput.value = projectId;
    titleElement.textContent = projectTitle;
    menteeElement.textContent = menteeName;
    
    // Reset mentor selection
    const mentorSelect = document.getElementById('mentorSelect');
    if (mentorSelect) mentorSelect.value = '';
    
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    
    // Focus on first interactive element for accessibility
    setTimeout(() => {
        const closeBtn = modal.querySelector('[data-close-modal]');
        if (closeBtn) closeBtn.focus();
    }, 100);
}

function closeModal() {
    const modal = document.getElementById('assignMentorModal');
    if (!modal) return;
    
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = 'auto';
    
    DashboardState.currentProject = null;
}

async function handleAssignMentor(e) {
    e.preventDefault();
    
    if (DashboardState.isLoading) return;
    
    const projectId = document.getElementById('projectId').value;
    const mentorId = document.getElementById('mentorSelect').value;
    
    if (!projectId || !mentorId) {
        showNotification('Please select a mentor', 'warning');
        return;
    }
    
    try {
        DashboardState.isLoading = true;
        showLoadingState(true, 'Assigning mentor...');
        
        const result = await apiCall(CONFIG.API_ENDPOINTS.MENTOR_MATCH, {
            method: 'POST',
            body: JSON.stringify({
                project_id: projectId,
                mentor_id: mentorId
            })
        });
        
        showNotification('Mentor assigned successfully!', 'success');
        closeModal();
        
        // Refresh data after short delay
        setTimeout(() => {
            loadAnalytics();
        }, CONFIG.AUTO_REFRESH_DELAY);
        
    } catch (error) {
        console.error('Error assigning mentor:', error);
        
        if (error.message.includes('CSRF') || error.message.includes('400')) {
            showNotification('Security token issue. Refreshing page...', 'error');
            // Attempt to refresh CSRF token and retry
            setTimeout(() => {
                location.reload();
            }, 2000);
        } else {
            showNotification(error.message || 'Failed to assign mentor', 'error');
        }
    } finally {
        DashboardState.isLoading = false;
        showLoadingState(false);
    }
}

async function handleRefresh() {
    if (DashboardState.isLoading) return;
    
    try {
        showNotification('Refreshing data...', 'info');
        await initDashboard();
        showNotification('Data refreshed successfully!', 'success');
    } catch (error) {
        console.error('Error refreshing dashboard:', error);
        showNotification('Failed to refresh data', 'error');
    }
}

function exportData() {
    // Basic export functionality
    const analyticsData = {
        timestamp: new Date().toISOString(),
        mentors: DashboardState.mentors.length,
        // Add more data as needed
    };
    
    const dataStr = JSON.stringify(analyticsData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `dashboard-export-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    
    showNotification('Data exported successfully!', 'success');
}

function showLoadingState(show, message = 'Loading...') {
    let loader = document.getElementById('dashboardLoader');
    
    if (show) {
        if (!loader) {
            loader = document.createElement('div');
            loader.id = 'dashboardLoader';
            loader.className = 'fixed inset-0 bg-white bg-opacity-75 flex items-center justify-center z-50';
            loader.innerHTML = `
                <div class="bg-white p-6 rounded-lg shadow-lg flex items-center space-x-3">
                    <div class="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
                    <span class="text-gray-700">${message}</span>
                </div>
            `;
            document.body.appendChild(loader);
        } else {
            loader.querySelector('span').textContent = message;
        }
    } else {
        if (loader) {
            loader.remove();
        }
    }
}

function initCharts() {
    // Initialize any charts if needed
    const chartContainers = document.querySelectorAll('[data-chart]');
    if (chartContainers.length > 0) {
        console.log('Charts initialized');
    }
}

function showNotification(message, type = 'info') {
    // Remove existing notification
    const existingNotification = document.querySelector('.custom-notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    const notification = document.createElement('div');
    notification.className = `custom-notification fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg text-white font-medium transform transition-transform duration-300 ${
        type === 'success' ? 'bg-green-500' :
        type === 'error' ? 'bg-red-500' :
        type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
    }`;
    notification.innerHTML = `
        <div class="flex items-center space-x-2">
            <span class="notification-icon">${getNotificationIcon(type)}</span>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-white hover:text-gray-200">×</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.classList.add('translate-x-0', 'opacity-100');
    }, 10);
    
    // Auto remove after configured duration
    setTimeout(() => {
        if (notification.parentElement) {
            notification.classList.remove('translate-x-0', 'opacity-100');
            setTimeout(() => notification.remove(), 300);
        }
    }, CONFIG.NOTIFICATION_DURATION);
}

function getNotificationIcon(type) {
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    return icons[type] || 'ℹ';
}

// Enhanced API call utility with CSRF token handling
async function apiCall(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    try {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        // Add CSRF token for non-GET requests if available
        if (options.method && options.method !== 'GET' && DashboardState.csrfToken) {
            headers['X-CSRF-Token'] = DashboardState.csrfToken;
        }
        
        const response = await fetch(url, {
            method: options.method || 'GET',
            headers,
            signal: controller.signal,
            credentials: 'same-origin', // Important for cookies and session
            ...options
        });
        
        clearTimeout(timeoutId);
        
        // Handle CSRF errors specifically
        if (response.status === 400) {
            const errorText = await response.text();
            if (errorText.includes('CSRF') || errorText.includes('token')) {
                throw new Error('CSRF token validation failed. Please refresh the page.');
            }
            throw new Error(`Bad Request: ${errorText}`);
        }
        
        if (response.status === 403) {
            throw new Error('Access forbidden. You may not have permission for this action.');
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText || response.statusText}`);
        }
        
        // For empty responses
        const contentLength = response.headers.get('content-length');
        if (contentLength === '0') {
            return null;
        }
        
        return await response.json();
    } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError') {
            throw new Error('Request timeout. Please try again.');
        }
        
        // Handle network errors
        if (error.message.includes('Failed to fetch')) {
            throw new Error('Network error. Please check your connection.');
        }
        
        throw error;
    }
}

// Add CSS for animations
const style = document.createElement('style');
style.textContent = `
    .stat-update {
        animation: pulse 0.5s ease-in-out;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    
    .custom-notification {
        transform: translateX(100%);
        opacity: 0;
        transition: all 0.3s ease-in-out;
    }
    
    .custom-notification.translate-x-0 {
        transform: translateX(0);
        opacity: 1;
    }
    
    .activity-item {
        padding: 0.5rem 0;
        border-bottom: 1px solid #e5e7eb;
    }
    
    .activity-time {
        font-size: 0.875rem;
        color: #6b7280;
        margin-right: 0.5rem;
    }
`;
document.head.appendChild(style);

// Export functions for global access
window.Dashboard = {
    initDashboard,
    openAssignMentorModal,
    closeModal,
    exportData,
    handleRefresh
};
