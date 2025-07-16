const API_BASE_URL = 'http://localhost:8000'; // Your FastAPI backend URL

// Function to fetch data from a given endpoint
async function fetchData(endpoint) {
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Could not fetch data from ${endpoint}:`, error);
        return null;
    }
}

// Function to safely update metric cards
function updateMetricCard(cardId, label, value) {
    const card = document.getElementById(cardId);
    if (!card) return;

    let valueColor = '';
    const numericValue = parseInt(value);

    if (!isNaN(numericValue) && numericValue > 0) {
        if (cardId.includes('spam') || cardId.includes('malware') ||
            cardId.includes('bruteForce') || cardId.includes('suspicious')) {
            valueColor = 'var(--danger-color)';
        } else if (cardId.includes('pending')) {
            valueColor = 'var(--warning-color)';
        } else {
            valueColor = 'var(--primary-color)';
        }
    } else {
        valueColor = 'var(--text-color)';
    }

    card.innerHTML = `<span>${label}</span><strong style="color: ${valueColor};">${value}</strong>`;
}

// Enhanced table creation function with column width control
function createTable(data, containerId, columns) {
    const container = document.querySelector(`#${containerId} .table-container`);
    if (!container) {
        console.error(`Table container with ID ${containerId} .table-container not found.`);
        return;
    }

    // Clear previous content
    container.innerHTML = '';

    if (!data || !Array.isArray(data) || data.length === 0) {
        container.innerHTML = '<div class="no-data">No data available</div>';
        return;
    }

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');

    // Create table header with explicit widths
    const headerRow = document.createElement('tr');
    columns.forEach(col => {
        const th = document.createElement('th');
        th.textContent = col.header || '';
        if (col.width) {
            th.style.width = col.width;
        }
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Create table body with safe data access
    data.forEach(item => {
        const row = document.createElement('tr');
        columns.forEach(col => {
            const td = document.createElement('td');
            let value = item?.[col.field] ?? '';
           
            // Apply formatting if specified
            if (col.format && typeof col.format === 'function') {
                try {
                    value = col.format(value);
                } catch (error) {
                    console.error(`Error formatting column ${col.field}:`, error);
                    value = '';
                }
            }
           
            // Handle HTML content safely
            if (typeof value === 'string' && value.includes('<')) {
                td.innerHTML = value;
            } else {
                td.textContent = value;
            }
           
            // Add severity coloring if applicable
            if (col.field === 'severity' && typeof value === 'string') {
                const severity = value.toLowerCase();
                if (severity.includes('high')) {
                    td.style.color = 'var(--danger-color)';
                    td.style.fontWeight = '600';
                } else if (severity.includes('medium')) {
                    td.style.color = 'var(--warning-color)';
                }
            }
           
            row.appendChild(td);
        });
        tbody.appendChild(row);
    });
   
    table.appendChild(tbody);
    container.appendChild(table);
}

// Function to update summary numbers
async function updateSummaryCounts() {
    try {
        const threatCounts = await fetchData('/threat-counts');
        if (!threatCounts) return;

        updateMetricCard('suspiciousIpCount', 'Suspicious IP Attempts', threatCounts.suspicious_ip_attempts);
        updateMetricCard('bruteForceCount', 'Brute Force Attacks', threatCounts.brute_force_attacks);
        updateMetricCard('malwareCount', 'Malware Detections', threatCounts.malware_detections);
        updateMetricCard('pendingAlertsCount', 'Pending Alerts', threatCounts.pending_threats);
        updateMetricCard('totalNetworkAlertsCount', 'Total Alerts', threatCounts.total_network_threats);
        updateMetricCard('totalEmailsCount', 'Total Emails', threatCounts.total_emails_received);
        updateMetricCard('spamEmailsCount', 'Spam Emails', threatCounts.spam_emails_detected);
        updateMetricCard('totalSmsCount', 'Total SMS', threatCounts.total_sms_received);
        updateMetricCard('spamSmsCount', 'Spam SMS', threatCounts.sms_spam_detected);
    } catch (error) {
        console.error('Error updating summary counts:', error);
    }
}

// Function to update lists/tables with better error handling
async function updateLists() {
    try {
        // Recent Threats (Security Insights)
        const recentThreats = await fetchData('/threats/recent');
       
        // Recent Email Logs
        const recentEmailLogs = await fetchData('/raw-email-logs');
        const emailLogColumns = [
            { header: 'Timestamp', field: 'received_timestamp', width: '20%', format: (ts) => ts ? new Date(ts).toLocaleString() : 'N/A' },
            { header: 'Sender', field: 'sender', width: '25%', format: (sender) => sender || 'Unknown' },
            { header: 'Subject', field: 'subject', width: '35%', format: (subj) => subj ? (subj.length > 30 ? subj.substring(0, 30) + '...' : subj) : 'No subject' },
            {
                header: 'Status',
                field: 'detection_status',
                width: '20%',
                format: (status) => {
                    if (!status) return 'Unknown';
                    const statusStr = String(status);
                    if (statusStr.toLowerCase().includes('spam')) {
                        return `<span style="color: var(--danger-color)">${statusStr}</span>`;
                    }
                    return statusStr;
                }
            },
        ];
        createTable(recentEmailLogs, 'recentEmailLogsContainer', emailLogColumns);

        // Recent SMS Logs
        const recentSmsLogs = await fetchData('/raw-sms-logs');
        const smsLogColumns = [
            { header: 'Timestamp', field: 'timestamp', width: '20%', format: (ts) => ts ? new Date(ts).toLocaleString() : 'N/A' },
            { header: 'Sender', field: 'sender_number', width: '25%', format: (sender) => sender || 'Unknown' },
            { header: 'Content', field: 'message_content', width: '35%', format: (content) => content ? (content.length > 30 ? content.substring(0, 30) + '...' : content) : 'No content' },
            {
                header: 'Status',
                field: 'detection_status',
                width: '20%',
                format: (status) => {
                    if (!status) return 'Unknown';
                    const statusStr = String(status);
                    if (statusStr.toLowerCase().includes('spam')) {
                        return `<span style="color: var(--danger-color)">${statusStr}</span>`;
                    }
                    return statusStr;
                }
            },
        ];
        createTable(recentSmsLogs, 'recentSmsLogsContainer', smsLogColumns);

        // Recent Network Threats
        if (recentThreats) {
            const networkThreatsOnly = recentThreats.filter(threat => threat?.source_type === "network_ids");
            const networkThreatColumns = [
                { header: 'Timestamp', field: 'timestamp', width: '20%', format: (ts) => ts ? new Date(ts).toLocaleString() : 'N/A' },
                { header: 'Threat Type', field: 'threat_type', width: '30%', format: (type) => type || 'Unknown' },
                { header: 'Source IP', field: 'source_identifier', width: '30%', format: (ip) => ip || 'Unknown' },
                { header: 'Severity', field: 'severity', width: '20%', format: (sev) => sev || 'Unknown' },
            ];
            createTable(networkThreatsOnly, 'recentNetworkThreatsContainer', networkThreatColumns);
        }

        // Security Insights Table
        if (recentThreats) {
            const securityInsightsColumns = [
                { header: 'Time', field: 'timestamp', width: '15%', format: (ts) => ts ? new Date(ts).toLocaleTimeString() : 'N/A' },
                {
                    header: 'Source',
                    field: 'source_type',
                    width: '20%',
                    format: (type) => {
                        if (!type) return 'Unknown';
                        const formatted = String(type).replace('_', ' ').toUpperCase();
                        if (type.includes('email')) return `<span style="color: var(--info-color)">${formatted}</span>`;
                        if (type.includes('sms')) return `<span style="color: var(--success-color)">${formatted}</span>`;
                        return formatted;
                    }
                },
                { header: 'Threat', field: 'threat_type', width: '30%', format: (type) => type || 'Unknown' },
                { header: 'Source ID', field: 'source_identifier', width: '20%', format: (id) => id || 'Unknown' },
                { header: 'Severity', field: 'severity', width: '15%', format: (sev) => sev || 'Unknown' },
            ];
            createTable(recentThreats, 'security-insights', securityInsightsColumns);
        }
    } catch (error) {
        console.error('Error updating lists:', error);
    }
}

// Initial data load and periodic refresh
document.addEventListener('DOMContentLoaded', () => {
    // Set active nav item
    const dashboardLink = document.querySelector('nav a[href="#Dashboard"]');
    if (dashboardLink) {
        dashboardLink.classList.add('active');
    }
   
    // Initial load
    updateSummaryCounts();
    updateLists();

    // Refresh data every 30 seconds
    const refreshInterval = setInterval(() => {
        updateSummaryCounts();
        updateLists();
    }, 30000);

    // Cleanup interval on page unload
    window.addEventListener('beforeunload', () => {
        clearInterval(refreshInterval);
    });
});