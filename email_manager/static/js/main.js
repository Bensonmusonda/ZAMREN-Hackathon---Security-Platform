// ZAMREN Cybersecurity Email Manager - Main JavaScript

// Global variables
let charts = {};
let currentTheme = 'light';

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    setupThemeToggle();
});

function initializeApp() {
    // Update active navigation
    updateActiveNavigation();
    
    // Initialize tooltips
    initializeTooltips();
    
    // Setup auto-refresh for dashboard
    if (window.location.pathname === '/') {
        startDashboardRefresh();
    }
}

function setupEventListeners() {
    // Form submissions
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', handleFormSubmission);
    });
    
    // File uploads
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.addEventListener('change', handleFileUpload);
    });
    
    // Modal events
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('show.bs.modal', handleModalShow);
        modal.addEventListener('hide.bs.modal', handleModalHide);
    });
}

function updateActiveNavigation() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
}

function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

function startDashboardRefresh() {
    // Refresh dashboard every 30 seconds
    setInterval(() => {
        if (document.visibilityState === 'visible') {
            refreshDashboardData();
        }
    }, 30000);
}

async function refreshDashboardData() {
    try {
        const response = await fetch('/api/dashboard-stats');
        const data = await response.json();
        
        // Update dashboard without full page reload
        updateDashboardElements(data);
    } catch (error) {
        console.error('Error refreshing dashboard:', error);
    }
}

function updateDashboardElements(data) {
    // Update threat count
    const threatCountElement = document.getElementById('threat-count');
    if (threatCountElement) {
        threatCountElement.textContent = data.total_threats;
    }
    
    // Update risk level
    const riskLevelElement = document.getElementById('risk-level');
    if (riskLevelElement) {
        riskLevelElement.textContent = data.risk_level;
        updateRiskLevelColor(riskLevelElement, data.risk_level);
    }
    
    // Update system status
    updateSystemStatus(data);
}

function updateRiskLevelColor(element, level) {
    element.className = element.className.replace(/text-\w+/, '');
    
    switch(level) {
        case 'CRITICAL':
            element.classList.add('text-danger');
            break;
        case 'HIGH':
            element.classList.add('text-warning');
            break;
        case 'MEDIUM':
            element.classList.add('text-info');
            break;
        default:
            element.classList.add('text-success');
    }
}

function updateSystemStatus(data) {
    const statusElement = document.getElementById('system-status');
    if (statusElement) {
        const icon = statusElement.querySelector('i');
        if (data.total_threats > 0) {
            icon.className = 'fas fa-circle text-warning';
            statusElement.innerHTML = '<i class="fas fa-circle text-warning"></i> Threats Detected';
        } else {
            icon.className = 'fas fa-circle text-success';
            statusElement.innerHTML = '<i class="fas fa-circle text-success"></i> System Active';
        }
    }
}

function handleFormSubmission(event) {
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    
    if (submitBtn && !submitBtn.disabled) {
        // Add loading state
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        submitBtn.disabled = true;
        
        // Restore button after delay if form doesn't redirect
        setTimeout(() => {
            if (submitBtn) {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }
        }, 5000);
    }
}

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (file) {
        // Validate file type
        const allowedTypes = ['text/csv', 'application/csv'];
        if (!allowedTypes.includes(file.type)) {
            showAlert('danger', 'Please select a valid CSV file');
            event.target.value = '';
            return;
        }
        
        // Validate file size (max 10MB)
        if (file.size > 10 * 1024 * 1024) {
            showAlert('danger', 'File size must be less than 10MB');
            event.target.value = '';
            return;
        }
        
        showAlert('success', `File "${file.name}" selected successfully`);
    }
}

function handleModalShow(event) {
    const modal = event.target;
    
    // Focus first input in modal
    setTimeout(() => {
        const firstInput = modal.querySelector('input, textarea, select');
        if (firstInput) {
            firstInput.focus();
        }
    }, 150);
}

function handleModalHide(event) {
    // Clear any form data in modal
    const forms = event.target.querySelectorAll('form');
    forms.forEach(form => {
        if (form.dataset.clearOnHide !== 'false') {
            form.reset();
        }
    });
}

function setupThemeToggle() {
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        currentTheme = savedTheme;
        applyTheme(currentTheme);
    }
}

function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(currentTheme);
    localStorage.setItem('theme', currentTheme);
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    
    // Update chart colors if charts exist
    Object.values(charts).forEach(chart => {
        if (chart && chart.options) {
            updateChartTheme(chart, theme);
        }
    });
}

function updateChartTheme(chart, theme) {
    const textColor = theme === 'dark' ? '#ffffff' : '#666666';
    const gridColor = theme === 'dark' ? '#404040' : '#e0e0e0';
    
    if (chart.options.scales) {
        Object.values(chart.options.scales).forEach(scale => {
            if (scale.ticks) scale.ticks.color = textColor;
            if (scale.grid) scale.grid.color = gridColor;
        });
    }
    
    if (chart.options.plugins && chart.options.plugins.legend) {
        chart.options.plugins.legend.labels.color = textColor;
    }
    
    chart.update();
}

// Utility Functions
function showAlert(type, message, duration = 5000) {
    const alertContainer = document.getElementById('alert-container') || document.querySelector('main');
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.style.position = 'relative';
    alertDiv.style.zIndex = '1050';
    
    alertDiv.innerHTML = `
        <i class="fas fa-${getAlertIcon(type)}"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.insertBefore(alertDiv, alertContainer.firstChild);
    
    // Auto-remove alert
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, duration);
    
    // Scroll to alert if not visible
    alertDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function getAlertIcon(type) {
    switch(type) {
        case 'success': return 'check-circle';
        case 'danger': return 'exclamation-triangle';
        case 'warning': return 'exclamation-circle';
        case 'info': return 'info-circle';
        default: return 'bell';
    }
}

function showConfirmDialog(message, callback) {
    const confirmed = confirm(message);
    if (confirmed && callback) {
        callback();
    }
    return confirmed;
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function formatRiskScore(score) {
    return `${score}/100`;
}

function getThreatLevelColor(level) {
    switch(level) {
        case 'CRITICAL': return 'danger';
        case 'HIGH': return 'warning';
        case 'MEDIUM': return 'info';
        default: return 'success';
    }
}

function getClassificationColor(classification) {
    if (classification.includes('SPAM') || classification.includes('PHISHING')) {
        return 'danger';
    } else if (classification === 'SUSPICIOUS') {
        return 'warning';
    } else {
        return 'success';
    }
}

// API Helper Functions
async function apiCall(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const mergedOptions = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, mergedOptions);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

async function uploadFile(url, file, additionalData = {}) {
    const formData = new FormData();
    formData.append('file', file);
    
    Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, value);
    });
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            body: formData,
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('File upload failed:', error);
        throw error;
    }
}

// Chart Helper Functions
function createChart(canvasId, config) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) {
        console.error(`Canvas with id "${canvasId}" not found`);
        return null;
    }
    
    const chart = new Chart(ctx.getContext('2d'), config);
    charts[canvasId] = chart;
    return chart;
}

function destroyChart(canvasId) {
    if (charts[canvasId]) {
        charts[canvasId].destroy();
        delete charts[canvasId];
    }
}

function updateChart(canvasId, newData) {
    const chart = charts[canvasId];
    if (chart) {
        chart.data = newData;
        chart.update();
    }
}

// Export functions for global access
window.ZamrenCyber = {
    showAlert,
    showConfirmDialog,
    formatTimestamp,
    formatRiskScore,
    getThreatLevelColor,
    getClassificationColor,
    apiCall,
    uploadFile,
    createChart,
    destroyChart,
    updateChart,
    toggleTheme
};